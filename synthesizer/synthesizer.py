import json
import sys
import re
import yaml
import subprocess
import fnmatch

from pathlib import Path
from z3 import *
from cmsis_svd.parser import (
  SVDParser,
  SVDDevice,
  SVDPeripheral,
  SVDRegister,
  SVDField,
  SVDInterrupt,
)
from typing import Dict, List, Mapping, Set, Tuple

DEFAULT_TIME_SCALE = 'us'

PERIPH_HOOKS = []

CR_REGEX = re.compile(r'(CR[0-9]*)|(C[0-9]*)')

class DMAInfo:
  def __init__(self) -> None:
    self.src = None
    self.dst = None
    self.cnt = None
    self.cond = None
    self.irq_cond = None
    self.enable_cond = None
    self.disable_cond = None
    self.channel_idx = None

class Synthesizer:
  def __init__(self, config_file: str, output_dir: str, all_in_one: bool, debug: bool) -> None:
    self.config_file = config_file
    self.output_dir = output_dir
    self.all_in_one = all_in_one
    self.debug = debug
    self.header_include = [
      'hw/sysbus.h',
      'qom/object.h'
    ]
    self.chardev_include = [
      'chardev/char-fe.h'
    ]
    self.eth_include = [
      'net/net.h',
      'net/eth.h',
      'sysemu/dma.h'
    ]
    self.src_include = [
      'qemu/osdep.h',
      'qemu/log.h',
      'qemu/bitops.h',
      'hw/sysbus.h',
      'hw/irq.h',
      'migration/vmstate.h',
      'hw/registerfields.h',
      'hw/resettable.h',
      'hw/qdev-properties-system.h',
      'exec/cpu-common.h'
    ]
    self.board_include = [
      'qemu/osdep.h',
      'qemu/units.h',
      'hw/sysbus.h',
      'qapi/error.h',
      'hw/arm/boot.h',
      'hw/arm/armv7m.h',
      'hw/boards.h',
      'exec/address-spaces.h',
      'hw/misc/unimp.h',
      'hw/clock.h',
      'hw/qdev-clock.h',
      'qom/object.h',
      'qemu/bitops.h',
      'hw/qdev-properties-system.h',
      'sysemu/sysemu.h'
    ]
    if self.all_in_one:
      all_in_one_include = self.src_include + self.header_include + self.board_include + self.chardev_include + self.eth_include
      self.all_in_one_include = []
      for x in all_in_one_include:
        if x not in self.all_in_one_include:
          self.all_in_one_include.append(x)
    else:
      self.all_in_one_include = []
    self.all_in_one_content = ''
    self.__parse_yaml()
    self.__setup_perry_cmdline()
    self.peripheral_results: Mapping[str, Tuple[str, str, str]] = {}
    self.board_result = None
    self.dma_struct_name = None
    self.dma_recv_func_name = None

  def __get_peripheral_base(self, p: SVDPeripheral) -> int:
    # p_derived_from = p.get_derived_from()
    # p_p = p
    # if p_derived_from is not None:
    #   p_p = p_derived_from
    # first_reg: SVDRegister = p_p.registers[0]
    # for r in p_p.registers:
    #   if r.address_offset < first_reg.address_offset:
    #     first_reg = r
    # return first_reg.address_offset + p._base_address
    return p._base_address

  def __get_peripheral_end(self, p: SVDPeripheral) -> int:
    p_derived_from = p.get_derived_from()
    p_p = p
    if p_derived_from is not None:
      p_p = p_derived_from
    last_reg: SVDRegister = p_p.registers[-1]
    for r in p_p.registers:
      if r.address_offset > last_reg.address_offset:
        last_reg = r
    if last_reg.derived_from is not None:
      for rr in p_p._lookup_possibly_derived_attribute("register_arrays"):
        if rr.name == last_reg.derived_from:
          last_reg._size = rr._size
          break
    return p._base_address + last_reg.address_offset + (last_reg._size >> 3)
  
  def __get_peripheral_size(self, p: SVDPeripheral) -> int:
    return self.__get_peripheral_end(p) - self.__get_peripheral_base(p)

  def __get_peripheral_size_lst(self, p: List[SVDPeripheral]) -> int:
    reg_ends = [self.__get_peripheral_end(pp) for pp in p]
    reg_ends = sorted(reg_ends, reverse=True)
    periph_base = self.__get_peripheral_base(p[0])
    return reg_ends[0] - periph_base
  
  def __parse_ar_archive(self, path: str) -> List[str]:
    contained_files = subprocess.check_output(['ar', '-t', path]).decode().strip()
    return contained_files.split('\n')
  
  def __extract_from_ar_archive(self, ar_path: str, name: str):
    os.system("ar -x {} {} --output={}".format(
      ar_path, name, Path(ar_path).parent
    ))

  def __setup_perry_cmdline(self):
    self.perry_common_cmd = []
    if self.debug:
      self.perry_common_cmd += ["gdb", "--args"]
    self.perry_common_cmd += [self.perry_path]

    shared_bitcode_generalized = set()
    for bc in self.shared_bitcode:
      bc_path = Path(bc)
      if bc_path.suffix == '.bca' or bc_path.suffix == ".a":
        # additional checks for *.bca and *.a
        for cbc in self.__parse_ar_archive(bc):
          cbc_path = bc_path.parent / cbc
          if not cbc_path.exists():
            self.__extract_from_ar_archive(bc, cbc);
          shared_bitcode_generalized.add(str(bc_path.parent / cbc))
      else:
        shared_bitcode_generalized.add(bc)
    self.shared_bitcode = list(shared_bitcode_generalized)
    
    self.perry_common_cmd += [
      "--allocate-determ",
      "--allocate-determ-start-address=0x20000000",
      "--allocate-determ-size=512",
      "--libc=none",
      "--output-stats=false",
      "--output-istats=false"
    ]

    if self.perry_memory_limit is not None:
      self.perry_common_cmd.append("--max-memory={}".format(self.perry_memory_limit))

    peripherals: List[SVDPeripheral] = self.device.peripherals

    periph_groups = []
    if self.peripheral_workload is not None:
      for pw in self.peripheral_workload:
        if '*' in pw['target'] or '?' in pw['target'] or '[' in pw['target']:
          periph_groups.append(pw['target'])

    # try resolve conflict
    all_ranges = []
    if len(periph_groups) > 0:
      periph_to_exclude = set()
      for pg in periph_groups:
        gps = []
        for p in peripherals:
          if fnmatch.fnmatch(p.name, pg):
            gps.append(p)
            periph_to_exclude.add(p.name)
        gps = sorted(gps, key=lambda x:x._base_address)
        _p_base = self.__get_peripheral_base(gps[0])
        _p_size = self.__get_peripheral_size_lst(gps)
        all_ranges.append((_p_base, _p_base + _p_size - 1))
      for p in peripherals:
        if p.name in periph_to_exclude:
          continue
        _p_base = self.__get_peripheral_base(p)
        _p_size = self.__get_peripheral_size(p)
        all_ranges.append((_p_base, _p_base + _p_size - 1))
    else:
      for p in peripherals:
        _p_base = self.__get_peripheral_base(p)
        _p_size = self.__get_peripheral_size(p)
        all_ranges.append((_p_base, _p_base + _p_size - 1))
    for p in self.additional_peripheral:
      all_ranges.append((p['base'], p['base'] + p['size'] - 1))
    
    all_ranges = sorted(all_ranges, key=lambda x:x[0])
    ranges_no_conflict = []
    prev_range = all_ranges[0]

    for i in range(1, len(all_ranges)):
      prev_end = prev_range[1]
      cur_begin = all_ranges[i][0]
      cur_end = all_ranges[i][1]
      if prev_end >= cur_begin:
        if cur_end <= prev_end:
          print("merging overlapping peripheral range [{}, {}] and [{}, {}]".format(
            hex(prev_range[0]), hex(prev_range[1]),
            hex(all_ranges[i][0]), hex(all_ranges[i][1])))
        else:
          print("merging (partially) overlapping peripheral range [{}, {}] and [{}, {}]".format(
            hex(prev_range[0]), hex(prev_range[1]),
            hex(all_ranges[i][0]), hex(all_ranges[i][1])))
          prev_range = (prev_range[0], all_ranges[i][1])
      else:
        # no conflict
        ranges_no_conflict.append(prev_range)
        prev_range = all_ranges[i]
    ranges_no_conflict.append(prev_range)
    
    for p in ranges_no_conflict:
      self.perry_common_cmd.append("--periph-address={}".format(hex(p[0])))
      self.perry_common_cmd.append("--periph-size={}".format(hex(p[1] - p[0] + 1)))
    
    if self.board_bitband:
      self.perry_common_cmd += [
        "--enable-bitband=true",
        "--bitband-region-address=0x40000000",
        "--bitband-alias-address=0x42000000",
        "--bitband-alias-size=0x02000000"
      ]
    
    if self.succ_ret_file:
      self.perry_common_cmd.append(
        "--perry-succ-ret-file={}".format(self.succ_ret_file))
    
    if self.loop_file:
      self.perry_common_cmd.append(
        "--perry-loop-file={}".format(self.loop_file))
    
    for ef in self.exclude_function:
      self.perry_common_cmd.append("--exclude-function-list={}".format(ef))
    
    for incf in self.include_function:
      self.perry_common_cmd.append("--include-function-list={}".format(incf))

    self.perry_common_cmd += [
      "--arm-cpu-version={}".format(self.cpu_type_name),
      "--write-no-tests=true",
      "--search=dfs",
      "--max-solver-time=10s",
      "--simplify-sym-indices=true",
      "--disable-verify=true",
    ]
  
  def __parse_yaml(self):
    with open(self.config_file, 'r') as f:
      y = yaml.safe_load(f)
    # SVD
    if 'svd' not in y:
      print("Must specify svd path in config file")
      sys.exit(10)
    config_file_path = Path(self.config_file)
    svd_path = config_file_path.parent / y['svd']
    svd_parser = SVDParser.for_xml_file(svd_path)
    self.device: SVDDevice = svd_parser.get_device()
    peripherals: List[SVDPeripheral] = self.device.peripherals
    self.name_to_peripheral: Mapping[str, SVDPeripheral] = {}
    for p in peripherals:
      self.name_to_peripheral[p.name] = p
          
    # prefix
    if 'prefix' in y:
      self.prefix = y['prefix']
    else:
      self.prefix = self.device.name
    self.prefix = self.prefix.lower()
    self.prefix_upper = self.prefix.upper()
    # peripherals workload
    if 'peripheral_workload' in y:
      self.peripheral_workload = y['peripheral_workload']
    else:
      self.peripheral_workload = None
    # board config
    if 'board_config' in y:
      self.board_config = y['board_config']
      self.__setup_board_ctx(self.board_config)
    else:
      self.board_config = None
    # sahred bitcode
    if 'bitcode' in y:
      relative_bc_path = []
      for bc in y['bitcode']:
        relative_bc_path.append(str(config_file_path.parent / bc))
      self.shared_bitcode = relative_bc_path
    else:
      self.shared_bitcode = []
    # perry path
    if 'perry-path' in y:
      perry_path = Path(y['perry-path'])
      if perry_path.is_absolute():
        self.perry_path = str(perry_path)
      else:
        perry_path = config_file_path.parent / perry_path
        if perry_path.exists():
          self.perry_path = str(perry_path)
        else:
          self.perry_path = 'perry'
    else:
      self.perry_path = 'perry'
    # additional peripheral
    if 'additional-peripheral' in y:
      self.additional_peripheral = y['additional-peripheral']
    else:
      self.additional_peripheral = []
    # perry memory limit
    if 'perry-memory-limit' in y:
      self.perry_memory_limit = y['perry-memory-limit']
    else:
      self.perry_memory_limit = None
    # success return file
    if 'success-ret-file' in y:
      self.succ_ret_file = str(config_file_path.parent / y['success-ret-file'])
    else:
      self.succ_ret_file = None
    # loop file
    if 'loop-file' in y:
      self.loop_file = str(config_file_path.parent / y['loop-file'])
    else:
      self.loop_file = None
    # excluded functions
    if 'exclude-function' in y:
      self.exclude_function = y['exclude-function']
    else:
      self.exclude_function = []
    # (additionally) included functions
    if 'include-function' in y:
      self.include_function = y['include-function']
    else:
      self.include_function = []
    if 'time-scale' in y:
      self.time_scale = y['time-scale']
    else:
      self.time_scale = None
    self.data_reg_periph = set()



  def __setup_peripheral_ctx(
    self,
    target: str,
    name: str,
    constraint_file: str
  ) -> None:
    ###############################
    ### parse constraints ###
    ###############################
    # data regs
    self.eth_desc_size = None
    self.eth_rx_desc_reg_offset = None
    self.eth_tx_desc_reg_offset = None
    self.eth_desc_tx_buf_len = None
    self.eth_desc_rx_frame_len = None
    self.eth_desc_buf = None
    self.eth_desc_rx_buf_len = None
    self.eth_desc_mem_layout = None
    self.eth_desc_next_desc = None
    self.eth_last_seg_constraints = None
    self.eth_avail_seg_constraints = None
    self.eth_first_seg_constraints = None
    self.eth_last_desc_constraints = None
    self.timer_period_reg_offset = None
    self.timer_counter_reg_offset = None
    self.timer_enable_constraints = None
    self.timer_disable_constraints = None
    self.timer_irq_constraints = None
    self.dma_src_dst_cnt_tuples = None
    self.dma_xfer_cplt_irq_conds = None
    self.dma_enable_conds = None
    self.dma_disable_conds = None
    self.dma_rx_enable_conds = None
    self.dma_rx_disable_conds = None
    self.dma_tx_enable_conds = None
    self.dma_tx_disable_conds = None
    self.has_update_func = False
    self.has_transmit_func = False

    if constraint_file is None:
      self.read_datareg_offset = []
      self.write_datareg_offset = []
      self.has_data_reg = False
      self.read_constraint = None
      self.write_constraint = None
      self.irq_constraint = None
      self.between_writes_constraint = None
      self.post_writes_constraint = None
      self.cond_actions: List[Tuple[ExprRef, ExprRef]] = []
    else:
      with open(constraint_file, 'r') as f:
        loaded_json = json.load(f)
      self.read_datareg_offset: List[int] = loaded_json['RD']
      self.write_datareg_offset: List[int] = loaded_json['WD']
      self.has_data_reg = len(self.read_datareg_offset)  > 0  or \
                          len(self.write_datareg_offset) > 0
      s1 = Solver()
      # read constraints
      s1.from_string(loaded_json['read_constraint'])
      exprs = s1.assertions();
      if len(exprs) == 0:
        self.read_constraint = None
      else:
        assert(len(exprs) == 1)
        self.read_constraint: ExprRef = exprs[0]
      # write constraints
      s1 = Solver()
      s1.from_string(loaded_json['write_constraint'])
      exprs = s1.assertions();
      if len(exprs) == 0:
        self.write_constraint = None
      else:
        assert(len(exprs) == 1)
        self.write_constraint: ExprRef = exprs[0]
      # irq constraints
      s1 = Solver()
      s1.from_string(loaded_json['irq_constraint'])
      exprs = s1.assertions();
      if len(exprs) == 0:
        self.irq_constraint = None
      else:
        assert(len(exprs) == 1)
        self.irq_constraint: ExprRef = exprs[0]
      # between writes constraints
      s1 = Solver()
      s1.from_string(loaded_json['between_writes_constraint'])
      exprs = s1.assertions();
      if len(exprs) == 0:
        self.between_writes_constraint = None
      else:
        assert(len(exprs) == 1)
        self.between_writes_constraint: ExprRef = exprs[0]
      # post writes constraints
      s1 = Solver()
      s1.from_string(loaded_json['post_writes_constraint'])
      exprs = s1.assertions();
      if len(exprs) == 0:
        self.post_writes_constraint = None
      else:
        assert(len(exprs) == 1)
        self.post_writes_constraint: ExprRef = exprs[0]
      # conditions and actions
      self.cond_actions: List[Tuple[ExprRef, ExprRef]] = []
      for pairs in loaded_json['cond_actions']:
        s1 = Solver()
        s1.from_string(pairs['cond'])
        cond = s1.assertions()[0]
        s1 = Solver()
        s1.from_string(pairs['action'])
        action = s1.assertions()[0]
        self.cond_actions.append((cond, action))
      # ETH
      if 'eth_desc_size' in loaded_json:
        self.eth_desc_size = loaded_json['eth_desc_size']
      if 'eth_rx_desc_reg_offset' in loaded_json:
        self.eth_rx_desc_reg_offset = loaded_json['eth_rx_desc_reg_offset']
      if 'eth_tx_desc_reg_offset' in loaded_json:
        self.eth_tx_desc_reg_offset = loaded_json['eth_tx_desc_reg_offset']
      if 'eth_desc_tx_buf_len' in loaded_json:
        self.eth_desc_tx_buf_len = loaded_json['eth_desc_tx_buf_len']
      if 'eth_desc_rx_frame_len' in loaded_json:
        self.eth_desc_rx_frame_len = loaded_json['eth_desc_rx_frame_len']
      if 'eth_desc_buf' in loaded_json:
        self.eth_desc_buf = loaded_json['eth_desc_buf']
      if 'eth_desc_rx_buf_len' in loaded_json:
        self.eth_desc_rx_buf_len = loaded_json['eth_desc_rx_buf_len']
      if 'eth_desc_mem_layout' in loaded_json:
        self.eth_desc_mem_layout = loaded_json['eth_desc_mem_layout']
      if 'eth_desc_next_desc' in loaded_json:
        self.eth_desc_next_desc = loaded_json['eth_desc_next_desc']
      if 'eth_last_seg_constraints' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['eth_last_seg_constraints'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.eth_last_seg_constraints = None
        else:
          assert(len(exprs) == 1)
          self.eth_last_seg_constraints: ExprRef = exprs[0]
      if 'eth_avail_seg_constraints' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['eth_avail_seg_constraints'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.eth_avail_seg_constraints = None
        else:
          assert(len(exprs) == 1)
          self.eth_avail_seg_constraints: ExprRef = exprs[0]
      if 'eth_first_seg_constraints' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['eth_first_seg_constraints'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.eth_first_seg_constraints = None
        else:
          assert(len(exprs) == 1)
          self.eth_first_seg_constraints: ExprRef = exprs[0]
      if 'eth_last_desc_constraints' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['eth_last_desc_constraints'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.eth_last_desc_constraints = None
        else:
          assert(len(exprs) == 1)
          self.eth_last_desc_constraints: ExprRef = exprs[0]
      if 'timer_period_reg_offset' in loaded_json:
        self.timer_period_reg_offset = loaded_json['timer_period_reg_offset']
      if 'timer_counter_reg_offset' in loaded_json:
        self.timer_counter_reg_offset = loaded_json['timer_counter_reg_offset']
      if 'timer_enable_action' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['timer_enable_action'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.timer_enable_constraints = None
        else:
          assert(len(exprs) == 1)
          self.timer_enable_constraints: ExprRef = exprs[0]
      if 'timer_disable_action' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['timer_disable_action'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.timer_disable_constraints = None
        else:
          assert(len(exprs) == 1)
          self.timer_disable_constraints: ExprRef = exprs[0]
      if 'timer_irq_cond' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['timer_irq_cond'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.timer_irq_constraints = None
        else:
          assert(len(exprs) == 1)
          self.timer_irq_constraints: ExprRef = exprs[0]
      # DMA
      if 'dma_src_dst_cnt_tuples' in loaded_json:
        self.dma_src_dst_cnt_tuples = loaded_json['dma_src_dst_cnt_tuples']
      if 'dma_xfer_cplt_irq_conds' in loaded_json:
        self.dma_xfer_cplt_irq_conds = loaded_json['dma_xfer_cplt_irq_conds']
      if 'dma_enable_conds' in loaded_json:
        self.dma_enable_conds = loaded_json['dma_enable_conds']
      if 'dma_disable_conds' in loaded_json:
        self.dma_disable_conds = loaded_json['dma_disable_conds']
      if 'dma_rx_enable_conds' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['dma_rx_enable_conds'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.dma_rx_enable_conds = None
        else:
          assert(len(exprs) == 1)
          self.dma_rx_enable_conds: ExprRef = self.__normalize_constraint(exprs[0])
      if 'dma_rx_disable_conds' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['dma_rx_disable_conds'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.dma_rx_disable_conds = None
        else:
          assert(len(exprs) == 1)
          self.dma_rx_disable_conds: ExprRef = self.__normalize_constraint(exprs[0])
      if 'dma_tx_enable_conds' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['dma_tx_enable_conds'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.dma_tx_enable_conds = None
        else:
          assert(len(exprs) == 1)
          self.dma_tx_enable_conds: ExprRef = self.__normalize_constraint(exprs[0])
      if 'dma_tx_disable_conds' in loaded_json:
        s1 = Solver()
        s1.from_string(loaded_json['dma_tx_disable_conds'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          self.dma_tx_disable_conds = None
        else:
          assert(len(exprs) == 1)
          self.dma_tx_disable_conds: ExprRef = self.__normalize_constraint(exprs[0])
    ############
    ### Misc ###
    ############
    # set target
    peripherals: List[SVDPeripheral] = self.device.peripherals
    self.target = None
    for p in peripherals:
      if p.get_derived_from() is None and fnmatch.fnmatch(p.name, target):
        if self.target is None:
          self.target = [p]
        else:
          self.target.append(p)
    if self.target is None:
      print("Failed to locate {}".format(target))
      sys.exit(11)
    self.target = sorted(self.target, key=lambda x:x._base_address)
    self.offset_to_reg = {}
    self.regs: List[SVDRegister] = []
    if self.target is not None:
      min_periph_base = self.target[0]._base_address
      for p in self.target:
        regs: List[SVDRegister] = p.registers
        for r in regs:
          if r.derived_from is not None:
            for rr in p._lookup_possibly_derived_attribute("register_arrays"):
              if rr.name == r.derived_from:
                r._fields = rr._fields
                r._size = rr._size
                r._access = rr._access
                r._reset_mask = r._reset_mask
                r._reset_value = rr._reset_value
        # reg_name_regex = re.compile(r'(.*)\[(\d+)\](.*)$')
        # idx = 0
        for r in regs:
          # if r._size != 0x20:
          #   print("In {}, the size of register {} is not 32 bits, "
          #         "which is not supported by now.".format(target, r.name))
          #   sys.exit(2)
          r.name = r.name.replace('[', '').replace(']', '')
          r.address_offset += (p._base_address - min_periph_base)
          if r.address_offset not in self.offset_to_reg:
            self.offset_to_reg[r.address_offset] = r
          
          # if (r.address_offset >> 2) != idx and self.has_data_reg:
          #   print("In {}, the index of register {} is not continuous, "
          #         "which is not supported by now.".format(target, r.name))
          #   sys.exit(3)
          # idx += 1
        self.regs += regs
    else:
      self.regs = []
    # sym name to regs
    self.sym_name_to_reg: Mapping[str, SVDRegister] = {}
    self.sym_name_regex = re.compile(r'^(\w+):(\d+):(\d+)$')
    ########################
    # normalize constraint #
    ########################
    self.read_constraint = self.__normalize_constraint(self.read_constraint)
    self.write_constraint = self.__normalize_constraint(self.write_constraint)
    self.between_writes_constraint = self.__normalize_constraint(
      self.between_writes_constraint
    )
    self.post_writes_constraint = self.__normalize_constraint(
      self.post_writes_constraint
    )
    self.irq_constraint = self.__normalize_constraint(self.irq_constraint)
    new_cond_actions: List[Tuple[ExprRef, ExprRef]] = []
    for pair in self.cond_actions:
      new_cond_actions.append((
        self.__normalize_constraint(pair[0]),
        self.__normalize_constraint(pair[1])
      ))
    self.cond_actions = new_cond_actions
    # collect irq-related regs
    self.irq_reg_offset = self.__collect_related_regs(self.irq_constraint)
    # collect data register read/write related regs
    self.data_related_reg_offset = set.union(
      self.__collect_related_regs(self.read_constraint),
      self.__collect_related_regs(self.write_constraint),
      self.__collect_related_regs(self.between_writes_constraint),
      self.__collect_related_regs(self.post_writes_constraint)
    )
    # collect regs used in cond-actions
    self.reg_offset_to_cond_actions: Mapping[int, List[Tuple[ExprRef, ExprRef, List[Int]]]] = {}
    for pair in self.cond_actions:
      cond_reg_offset = self.__collect_related_regs(pair[0])
      action_reg_offset = self.__collect_related_regs(pair[1]);
      for co in cond_reg_offset:
        if co not in self.reg_offset_to_cond_actions:
          self.reg_offset_to_cond_actions[co] = []
        self.reg_offset_to_cond_actions[co].append(pair + (action_reg_offset,))
    # collect DMA channel infos
    self.dma_channel_infos: Dict[int, List[DMAInfo]] = None
    num_channels = 0
    if self.dma_src_dst_cnt_tuples is not None:
      self.dma_channel_infos = {}
      cnt_regs = []
      for src_dst_cnt_tuple in self.dma_src_dst_cnt_tuples:
        if src_dst_cnt_tuple['cnt'] not in cnt_regs:
          cnt_regs.append(src_dst_cnt_tuple['cnt'])
      cnt_regs.sort()
      num_channels = len(cnt_regs)
      for src_dst_cnt_tuple in self.dma_src_dst_cnt_tuples:
        channel_idx = None
        for i in range(0, len(cnt_regs)):
          if src_dst_cnt_tuple['cnt'] == cnt_regs[i]:
            channel_idx = i
            break
        if channel_idx is None:
          continue
        if channel_idx not in self.dma_channel_infos:
          self.dma_channel_infos[channel_idx] = []
        new_dma_info = DMAInfo()
        new_dma_info.channel_idx = channel_idx
        new_dma_info.cnt = src_dst_cnt_tuple['cnt']
        new_dma_info.src = src_dst_cnt_tuple['src']
        new_dma_info.dst = src_dst_cnt_tuple['dst']
        s1 = Solver()
        s1.from_string(src_dst_cnt_tuple['cond'])
        exprs = s1.assertions();
        if len(exprs) == 0:
          new_dma_info.cond = None
        else:
          assert(len(exprs) == 1)
          new_dma_info.cond: ExprRef = self.__normalize_constraint(exprs[0])
        self.dma_channel_infos[channel_idx].append(new_dma_info)
    if self.dma_xfer_cplt_irq_conds is not None:
      if self.dma_channel_infos is None:
        self.dma_channel_infos = {}
      for ic in self.dma_xfer_cplt_irq_conds:
        s1 = Solver()
        s1.from_string(ic['cond'])
        exprs = s1.assertions();
        ice = None
        if len(exprs) == 1:
          ice = self.__normalize_constraint(exprs[0])
        if ic['channel'] not in self.dma_channel_infos:
          self.dma_channel_infos[ic['channel']] = []
          new_dma_info = DMAInfo()
          new_dma_info.channel_idx = ic['channel']
          new_dma_info.irq_cond = ice
          self.dma_channel_infos[new_dma_info.channel_idx].append(new_dma_info)
        else:
          for dci in self.dma_channel_infos[ic['channel']]:
            dci.irq_cond = ice
    if self.dma_enable_conds is not None:
      if self.dma_channel_infos is None:
        self.dma_channel_infos = {}
      dma_enables_conds = []
      for ec in self.dma_enable_conds:
        s1 = Solver()
        s1.from_string(ec)
        exprs = s1.assertions();
        if len(exprs) == 1:
          dma_enables_conds.append(self.__normalize_constraint(exprs[0]))
      dma_enable_regs = []
      for dec in dma_enables_conds:
        tmp = self.__collect_related_regs(dec).pop()
        if tmp not in dma_enable_regs:
          dma_enable_regs.append(tmp)
      dma_enable_regs.sort()
      for dec in dma_enables_conds:
        tmp = self.__collect_related_regs(dec).pop()
        channel_idx = None
        for i in range(0, len(dma_enable_regs)):
          if tmp == dma_enable_regs[i]:
            channel_idx = i
            break
        if channel_idx is None:
          continue
        if channel_idx not in self.dma_channel_infos:
          self.dma_channel_infos[channel_idx] = []
          new_dma_info = DMAInfo()
          new_dma_info.channel_idx = channel_idx
          new_dma_info.enable_cond = dec
          self.dma_channel_infos[channel_idx].append(new_dma_info)
        else:
          for dci in self.dma_channel_infos[channel_idx]:
            dci.enable_cond = dec
    if self.dma_disable_conds is not None:
      if self.dma_channel_infos is None:
        self.dma_channel_infos = {}
      dma_disable_conds = []
      for ec in self.dma_disable_conds:
        s1 = Solver()
        s1.from_string(ec)
        exprs = s1.assertions();
        if len(exprs) == 1:
          dma_disable_conds.append(self.__normalize_constraint(exprs[0]))
      dma_disable_regs = []
      for dec in dma_disable_conds:
        tmp = self.__collect_related_regs(dec).pop()
        if tmp not in dma_disable_regs:
          dma_disable_regs.append(tmp)
      dma_disable_regs.sort()
      for dec in dma_disable_conds:
        tmp = self.__collect_related_regs(dec).pop()
        channel_idx = None
        for i in range(0, len(dma_disable_regs)):
          if tmp == dma_disable_regs[i]:
            channel_idx = i
            break
        if channel_idx is None:
          continue
        if channel_idx not in self.dma_channel_infos:
          self.dma_channel_infos[channel_idx] = []
          new_dma_info = DMAInfo()
          new_dma_info.channel_idx = channel_idx
          new_dma_info.disable_cond = dec
          self.dma_channel_infos[channel_idx].append(new_dma_info)
        else:
          for dci in self.dma_channel_infos[channel_idx]:
            dci.disable_cond = dec
    # name
    if name is None or len(name) == 0:
      self.name = target
    else:
      self.name = name
    self.name = self.name.lower()
    self.name_upper = self.name.upper()
    self.header_def = "__{}_{}_H__".format(self.prefix_upper, self.name_upper)
    self.full_name = "{}_{}".format(self.prefix, self.name)
    self.full_name_upper = self.full_name.upper()
    self.type_name = "TYPE_{}".format(self.full_name_upper)
    self.symbol_name = "{}-{}".format(self.prefix, self.name)
    self.symbol_name_upper = self.symbol_name.upper()
    self.struct_name = "{}{}".format(self.prefix_upper, self.name_upper)
    self.register_types_func_name = "{}_register_types".format(self.full_name)
    self.info_struct_name = "{}_info".format(self.full_name)
    self.init_func_name = "{}_init".format(self.full_name)
    self.class_init_func_name = "{}_class_init".format(self.full_name)
    self.properties_struct_name = "{}_properties".format(self.full_name)
    self.vmstate_struct_name = "{}_vmstate".format(self.full_name)
    self.reset_enter_func_name = "{}_reset_enter".format(self.full_name)
    self.realize_func_name = "{}_realize".format(self.full_name)
    self.register_reset_func_name = "{}_register_reset".format(self.full_name)
    self.ops_struct_name = "{}_ops".format(self.full_name)
    self.read_func_name = "{}_read".format(self.full_name)
    self.write_func_name = "{}_write".format(self.full_name)
    self.periph_size_def = "{}_SIZE".format(self.full_name_upper)
    self.update_func_name = "{}_update".format(self.full_name)
    self.periph_instance_name = 't'
    self.can_receive_func_name = "{}_can_receive".format(self.full_name)
    self.receive_func_name = "{}_receive".format(self.full_name)
    self.transmit_func_name = "{}_transmit".format(self.full_name)
    self.eth_info_struct_name = "net_{}_info".format(self.full_name)
    self.eth_timer_callback_func_name = "{}_timer_callback".format(self.full_name)
    self.eth_dma_desc_struct_name = "ETH_DMADescTypeDef"
    self.eth_send_func_name = "{}_net_send".format(self.full_name)
    self.eth_can_receive_func_name = "{}_net_can_receive".format(self.full_name)
    self.eth_receive_func_name = "{}_net_receive".format(self.full_name)
    self.src_include.append('{}.h'.format(self.symbol_name))
    self.timer_callback_func_name = "{}_timer_callback".format(self.full_name)
    if self.dma_channel_infos is not None:
      self.dma_struct_name = self.struct_name
  
  def __setup_board_ctx(self, y):
    self.cpu_type_name = y['cpu']
    self.machine_name = y['machine_name']
    self.machine_name_upper = self.machine_name.upper()
    self.machine_type_conv = '{}_MACHINE'.format(self.machine_name_upper)
    self.machine_get_class = '{}_GET_CLASS'.format(self.machine_type_conv)
    self.machine_class = '{}_CLASS'.format(self.machine_type_conv)
    self.machine_type_def = 'TYPE_{}_MACHINE'.format(self.machine_name_upper)
    self.machine_state_struct_name = '{}MachineState'.format(self.machine_name_upper)
    self.machine_class_struct_name = '{}MachineClass'.format(self.machine_name_upper)
    self.board_init_func_name = '{}_machine_init'.format(self.machine_name)
    self.board_info_struct_name = '{}_info'.format(self.machine_name)
    self.board_class_init_func_name = '{}_class_init'.format(self.machine_name)
    self.board_common_init_func_name = '{}_common_init'.format(self.machine_name)
    self.board_periph_init_func_name = '{}_periph_init'.format(self.machine_name)
    self.clk_freq = y['clk_freq']
    self.num_irq = y['num_irq']
    self.init_vtor = y['init_vtor']
    self.memory_regions = y['memory']
    self.board_peripherals = y['peripheral']
    self.board_bitband = y['bitband']
    self.flash_size = None
    for p in self.board_peripherals:
      self.board_include.append('{}-{}.h'.format(self.prefix, p['kind'].lower()))
  
  def __normalize_constraint(self, expr: ExprRef) -> ExprRef:
    def collect_syms(expr: ExprRef) -> List[ExprRef]:
      WL: List[ExprRef] = []
      WL.append(expr)
      ret = []
      while len(WL) > 0:
        cur = WL.pop()
        if not is_app(cur):
          continue
        kind = cur.decl().kind()
        if kind == Z3_OP_EXTRACT:
          ret.append(cur)
        for arg in cur.children():
          WL.append(arg)
      return ret
    
    if expr is None:
      return None
    syms = collect_syms(expr)
    for sym in syms:
      bv_const = sym.arg(0)
      assert(is_bv(bv_const) and is_const(bv_const))
      bv_name = bv_const.decl().name()
      match_group = self.sym_name_regex.match(bv_name).groups()
      bv_offset = int(match_group[1])
      if bv_offset not in self.offset_to_reg:
        norm_offset = bv_offset
        while True:
          norm_offset -= 1
          if norm_offset in self.offset_to_reg:
            break
        the_reg: SVDRegister = self.offset_to_reg[norm_offset]
        new_bv_name = "{}:{}:{}".format(match_group[0], norm_offset, the_reg._size)
        new_bv_const = BitVec(new_bv_name, the_reg._size)
        high, lo = sym.params()
        expr = substitute(
          expr, (
            sym,
            Extract(
              high + (bv_offset - norm_offset) * 8,
              lo + (bv_offset - norm_offset) * 8,
              new_bv_const
            )
          )
        )
    return expr
  
  def __collect_related_regs(self, expr: ExprRef) -> Set[int]:
    reg_offset_set: Set[int] = set()
    if expr is None:
      return reg_offset_set
    WL: List[ExprRef] = []
    WL.append(expr)
    while len(WL) > 0:
      cur = WL.pop()
      if not is_app(cur):
        continue
      cur_kind = cur.decl().kind()
      if cur_kind == Z3_OP_AND  or \
         cur_kind == Z3_OP_OR   or \
         cur_kind == Z3_OP_XOR  or \
         cur_kind == Z3_OP_NOT:
        assert(is_bool(cur))
        for arg in cur.children():
          WL.append(arg)
      elif cur_kind == Z3_OP_EQ:
        left: ExprRef = cur.arg(0)
        right: ExprRef = cur.arg(1)
        if left.decl().kind() == Z3_OP_EXTRACT:
          sym_name = left.arg(0).decl().name()
        elif is_const(left):
          sym_name = left.decl().name()
        else:
          print("should not happen")
          sys.exit(20)
        assert(is_bv_value(right) or (is_bv(right)))
        reg_offset = int(self.sym_name_regex.match(sym_name).groups()[1])
        if sym_name not in self.sym_name_to_reg:
          # reg_idx = (reg_idx >> 2)
          self.sym_name_to_reg[sym_name] = self.offset_to_reg[reg_offset]
        reg_offset_set.add(reg_offset)
      else:
        print("should not happen")
        sys.exit(6)
    return reg_offset_set
            
  def __register_size_to_type(self, size: int) -> str:
    if size == 0x20:
      return 'uint32_t'
    elif size == 0x10:
      return 'uint16_t'
    elif size == 0x08:
      return 'uint8_t'
    else:
      return None
  
  def __z3_expr_to_cond(self, expr: ExprRef, value:str="") -> str:
    # what do we support: and, or, xor, not, eq, extract
    # traverse the tree
    class StackCell:
      def __init__(self, kind=None, num_args=None) -> None:
        if kind is not None:
          self.flag = True
          assert(num_args is not None)
          self.kind = kind
          self.num_args = num_args
        else:
          self.flag = False
          self.kind = None
          self.num_args = None
    
    op_stack: List[StackCell] = []
    operand_stack: List[ExprRef] = []
    WL: List[ExprRef] = []
    WL.append(expr)
    while len(WL) > 0:
      cur = WL.pop()
      if not is_app(cur):
        continue
      cur_kind = cur.decl().kind()
      if cur_kind == Z3_OP_AND  or \
         cur_kind == Z3_OP_OR   or \
         cur_kind == Z3_OP_XOR  or \
         cur_kind == Z3_OP_NOT:
        assert(is_bool(cur))
        num_args = cur.num_args()
        op_stack.append(StackCell(cur_kind, num_args))
        for i in range(num_args, 0, -1):
          WL.append(cur.arg(i - 1))
      elif cur_kind == Z3_OP_EQ:
        left: ExprRef = cur.arg(0)
        right: ExprRef = cur.arg(1)
        assert(left.decl().kind() == Z3_OP_EXTRACT or is_const(left))
        assert(is_bv_value(right) or (is_const(right) and is_bv(right)))
        operand_stack.append(cur)
        op_stack.append(StackCell())
      else:
        print("should not happen")
        sys.exit(5)
    
    sub_expr: List[str] = []
    while len(op_stack) > 0:
      sc = op_stack.pop()
      if sc.flag:
        num_args = sc.num_args
        cur_kind = sc.kind
        if cur_kind == Z3_OP_AND  or \
           cur_kind == Z3_OP_OR   or \
           cur_kind == Z3_OP_XOR:
          assert(num_args > 1)
          tmp = sub_expr.pop()
          for _ in range(num_args - 1):
            another = sub_expr.pop()
            hyphen = None
            if cur_kind == Z3_OP_AND:
              hyphen = '&&'
            elif cur_kind == Z3_OP_OR:
              hyphen = '||'
            else:
              hyphen = '^'
            tmp = '{} {} {}'.format(tmp, hyphen, another)
          sub_expr.append('({})'.format(tmp))
        else:
          assert(cur_kind == Z3_OP_NOT)
          assert(num_args == 1)
          tmp = sub_expr.pop()
          sub_expr.append('(!{})'.format(tmp))
      else:
        operand: ExprRef = operand_stack.pop()
        left = operand.arg(0)   # extract
        right = operand.arg(1)  # const
        is_eth_desc = False
        if is_const(left):
          sym_name: str = left.decl().name()
        else:
          sym_name: str = left.arg(0).decl().name()
        if sym_name not in self.sym_name_to_reg:
          grp = self.sym_name_regex.match(sym_name).groups()
          reg_offset = int(grp[1])
          num_bits = int(grp[2])
          if grp[0] == 'd':
            is_eth_desc = True
          else:
            self.sym_name_to_reg[sym_name] = self.offset_to_reg[reg_offset]
          # reg_idx = (reg_idx >> 2)
        if not is_eth_desc:
          target_reg = self.sym_name_to_reg[sym_name]
        if not is_bv_value(right):
          sub_expr.append("")
        else:
          right_val = right.as_long()
          if is_eth_desc:
            lhs = "*((uint{}_t *)(((uint8_t *)&{}) + {}))".format(num_bits, value, reg_offset)
          elif len(value) > 0:
            lhs = value
          else:
            lhs = '{}->{}'.format(self.periph_instance_name, target_reg.name)
          if is_const(left):
            tmp = '({} == {})'.format(lhs, hex(right_val))
          else:
            extract_high, extract_low = left.params()
            mask = 0
            while extract_low <= extract_high:
              mask |= (1 << extract_low)
              extract_low += 1
            if right_val == 1:
              tmp = '({} & {})'.format(lhs, hex(mask))
            else:
              assert(right_val == 0)
              tmp = '(!({} & {}))'.format(lhs, hex(mask))
          sub_expr.append(tmp)
    assert(len(sub_expr) == 1)
    return sub_expr.pop()

  def __get_linear_formula(self, expr: ExprRef, value:str="value") -> str:
    if is_bv_value(expr):
      return str(expr.as_long())
    elif is_const(expr):
      assert(expr.decl().name().startswith("tmp"))
      return value
    else:
      expr_kind = expr.decl().kind()
      if expr_kind == Z3_OP_BADD:
        return "{} + {}".format(
          self.__get_linear_formula(expr.arg(0)),
          self.__get_linear_formula(expr.arg(1)))
      elif expr_kind == Z3_OP_BMUL:
        return "{} * {}".format(
          self.__get_linear_formula(expr.arg(0)),
          self.__get_linear_formula(expr.arg(1)))
      else:
        assert(False and "Should not happen")
    
  
  def __z3_expr_to_reg(
      self, expr: ExprRef,
      is_set: bool,
      value:str="value",
      do_filter=False
    ) -> Set[str]:
    # For now, we only support AND, NOT, EQ. 
    # Note that the AND expr must not be a sub-expr of NOT. Otherwise we may
    # have multiple options, and we need to ask the solver to workout a proper
    # model. But empirically these situations rarely happen.
    WL: List[ExprRef] = []
    WL.append(expr)
    set_expr: List[ExprRef] = []
    reg_ops: Set[str] = set()
    while len(WL) > 0:
      cur = WL.pop()
      assert(is_app(cur))
      cur_kind = cur.decl().kind()
      if cur_kind == Z3_OP_AND:
        for s in cur.children():
          WL.append(s)
      elif cur_kind == Z3_OP_NOT:
        assert(cur.arg(0).decl().kind() == Z3_OP_EQ)
        set_expr.append(cur)
      elif cur_kind == Z3_OP_EQ:
        set_expr.append(cur)
      elif cur_kind == Z3_OP_OR:
        for s in cur.children():
          WL.append(s)
      else:
        print("Not supported z3 expr {}, ignore".format(cur))
        # sys.exit(8)
        return []
    for e in set_expr:
      should_add = True
      e_kind = e.decl().kind()
      eq_expr = None
      needs_negate = False
      if e_kind == Z3_OP_NOT:
        needs_negate = True
        eq_expr = e.arg(0)
      else:
        assert(e_kind == Z3_OP_EQ)
        eq_expr = e
      assert(is_app(eq_expr))
      assert(eq_expr.decl().kind() == Z3_OP_EQ)
      left: ExprRef = eq_expr.arg(0)
      right: ExprRef = eq_expr.arg(1)
      assert(left.decl().kind() == Z3_OP_EXTRACT or (is_const(left) and is_bv(left)))
      assert(is_bv_value(right) or is_bv(right))
      if is_const(left):
        sym_name = left.decl().name()
      else:
        sym_name = left.arg(0).decl().name()
      is_eth = False
      if sym_name not in self.sym_name_to_reg:
        grp = self.sym_name_regex.match(sym_name).groups()
        reg_offset = int(grp[1])
        num_bits = int(grp[2])
        if grp[0] == 'd':
          is_eth = True
        else:
        # reg_idx = (reg_idx >> 2)
          self.sym_name_to_reg[sym_name] = self.offset_to_reg[reg_offset]
      if not is_eth:
        target_reg = self.sym_name_to_reg[sym_name]
      real_set = is_set ^ needs_negate
      if is_bv_value(right):
        right_val = right.as_long()
        assert(right_val == 1)
        extract_high, extract_low = left.params()
        mask = 0
        while extract_low <= extract_high:
          mask |= (1 << extract_low)
          extract_low += 1
        if is_eth:
          body = "*((uint{}_t *)(((uint8_t *)&{}) + {}))".format(num_bits, value, reg_offset)
        else:
          body = '{}->{}'.format(self.periph_instance_name, target_reg.name)
          if do_filter:
            if CR_REGEX.fullmatch(target_reg.name) is not None:
              should_add = False
        if real_set:
          body += ' |= {};'.format(hex(mask))
        else:
          body += ' &= (~({}));'.format(hex(mask))
      else:
        # linear formula?
        assert(real_set)
        body = '{}->{} = {};'.format(
          self.periph_instance_name,
          target_reg.name,
          self.__get_linear_formula(right, value))
        if do_filter:
          if CR_REGEX.fullmatch(target_reg.name) is not None:
            should_add = False
      if should_add:
        reg_ops.add(body)
    return reg_ops

  def __get_field(self, obj, field) -> str:
    offset = field[0]
    start_bit = field[1]
    num_bits = field[2]
    body = '((uint8_t*)(&{}))'.format(obj)
    if offset > 0:
      body = '(*((uint32_t*)({} + {})))'.format(body, offset)
    else:
      body = '(*((uint32_t*)({})))'.format(body, offset)
    if start_bit > 0:
      body = '({} >> {})'.format(body, start_bit)
    if num_bits > 0 and num_bits < 32:
      mask = 0
      for i in range(num_bits):
        mask |= (1 << i)
      body = '({} & {})'.format(body, hex(mask))
    return body

  def __set_field(self, obj, field, value) -> str:
    offset = field[0]
    start_bit = field[1]
    num_bits = field[2]
    body = '((uint8_t*)(&{}))'.format(obj)
    bit_length = num_bits + start_bit
    if bit_length <= 32:
      bit_length = 32
    if offset > 0:
      body = '*((uint{}_t*)({} + {}))'.format(bit_length, body, offset)
    else:
      body = '*((uint{}_t*)({}))'.format(bit_length, body, offset)
    tmp = ''
    if num_bits > 0 and num_bits < 32:
      mask = 0
      for i in range(num_bits):
        mask |= (1 << i)
      tmp = '({} & {})'.format(value, hex(mask))
    elif num_bits == 32:
      tmp = '({})'.format(value)
    if start_bit > 0:
      tmp = '({} << {})'.format(tmp, start_bit)
    zero_expr = '(~({} << {}))'.format(hex(mask), start_bit)
    return '{0} &= {1}; {0} |= {2}'.format(body, zero_expr, tmp)
  
  def __eth_get_eth_desc_rx_buf_len(self, value='') -> str:
    if isinstance(self.eth_desc_rx_buf_len, int):
      return 't->{}'.format(self.offset_to_reg[self.eth_desc_rx_buf_len].name)
    else:
      return self.__get_field(value, self.eth_desc_rx_buf_len)
  
  def __eth_get_next_desc(self, value='') -> str:
    if self.eth_desc_mem_layout == 'RINGBUF':
      return self.__get_field(value, self.eth_desc_next_desc)
    elif self.eth_desc_mem_layout == 'ARRAY':
      return '{} + {}'.format(value, self.eth_desc_size)
    else:
      print("should not happen")
      exit(2)
  
  def _gen_header_include(self) -> str:
    body = ''
    for item in self.header_include:
      body += '#include "{}"\n'.format(item)
    if self.has_data_reg:
      for item in self.chardev_include:
        body += '#include "{}"\n'.format(item)
    if self.eth_rx_desc_reg_offset is not None:
      for item in self.eth_include:
        body += '#include "{}"\n'.format(item)
    body += '\n'
    return body
  
  def _gen_header_qom_def(self) -> str:
    body = \
"""
#define {0} \"{1}\"
OBJECT_DECLARE_SIMPLE_TYPE({2}, {3})
"""
    body = body.format(
      self.type_name, self.symbol_name, self.struct_name, self.full_name_upper
    )
    return body
  
  def _gen_header_struct(self) -> str:
    body = \
"""
struct {0} {{
\t/* parent */
\tSysBusDevice parent;

\t/* memory mapping */
\tMemoryRegion iomem;

{1}
}};
"""
    content = ''
    # irqs
    num_irq = 0
    for p in self.target:
      if p._interrupts:
        num_irq += len(p._interrupts)
    if num_irq > 0:
      content += '\t/* irqs */\n'
      content += '\tqemu_irq irq[{}];\n\n'.format(num_irq)
    # registers
    content += '\t/*registers*/\n'
    gened = set()
    for r in self.regs:
      if r.name in gened:
        continue
      gened.add(r.name)
      reg_type = self.__register_size_to_type(r._size)
      if reg_type is None:
        print(
          "In {}, the register {} has size {}, which is nor supported".format(
            self.target, r.name, r._size
          )
        )
        sys.exit(4)
      content += '\t{} {};\n'.format(reg_type, r.name)
    # chardev backend
    if self.has_data_reg:
      content += '\t/* chardev backend */\n'
      content += '\tCharBackend chr;\n'
      content += '\tguint watch_tag;\n\n'
    if self.eth_rx_desc_reg_offset is not None:
      content += '\t/* Network backend */\n'
      content += '\tNICState *nic;\n'
      content += '\tNICConf conf;\n\n'
      content += '\t/* Timer for DMA polling */\n'
      content += '\tQEMUTimer *timer;\n\n'
      content += '\t/* additional states */\n'
      content += '\tuint32_t cur_rx_descriptor;\n\n'
      content += '\tuint32_t cur_tx_descriptor;\n\n'
    if self.timer_counter_reg_offset is not None:
      content += '\t/* timer */\n'
      content += '\tQEMUTimer *timer;\n'
      content += '\tuint8_t enabled;\n\n'
    if self.dma_struct_name is not None:
      if self.dma_rx_enable_conds is not None:
        content += '\t/* dma */\n'
        content += '\t{} *dma;\n'.format(self.dma_struct_name)
      if self.dma_channel_infos is not None:
        content += '\t/* dma channel enable flags*/\n'
        content += '\tuint8_t channel_enabled[{}];\n'.format(len(self.dma_channel_infos))
    content += '\t/* base */\n'
    content += '\tuint32_t base;\n'
    body = body.format(self.struct_name, content)
    return body

  def _gen_src_include(self) -> str:
    body = ''
    for item in self.src_include:
      body += '#include "{}"\n'.format(item)
    body += '\n'
    return body
  
  def _gen_src_macros(self) -> str:
    body = ''
    body += '#define {}\t\t\t\t{}\n\n'.format(
      self.periph_size_def, hex(self.__get_peripheral_size_lst(self.target))
    )
    gened = {}
    for r in self.regs:
      if not self.all_in_one:
        name_to_use = r.name
      else:
        name_to_use = '{}_{}'.format(self.name_upper, r.name)
      fields: List[SVDField] = r._fields
      if name_to_use in gened:
        for f in fields:
          if f.name not in gened[name_to_use]:
            gened[name_to_use].append(f.name)
            body += '\tFIELD({}, {}, {}, {})\n'.format(
              name_to_use, f.name, f.bit_offset, f.bit_width
            )
      else:
        gened[name_to_use] = [f.name for f in fields]
        body += 'REG{}({}, {})\n'.format(r._size, name_to_use, hex(r.address_offset))
        for f in fields:
          body += '\tFIELD({}, {}, {}, {})\n'.format(
            name_to_use, f.name, f.bit_offset, f.bit_width
          )
    body += '\n'
    return body
  
  def _gen_src_register_reset_func(self) -> str:
    body = \
"""
static void {0}({1} *{2}) {{
{3}
}}
"""
    content = ''
    for r in self.regs:
      if r._reset_value is not None:
        content += '\t{}->{} = {};\n'.format(
          self.periph_instance_name, r.name, hex(r._reset_value)
        )
    # reset write conditions
    wc_reset_exprs = set()
    if self.write_constraint is not None:
      wc_reset_exprs = wc_reset_exprs.union(self.__z3_expr_to_reg(self.write_constraint, True, do_filter=True))
    if self.between_writes_constraint is not None:
      wc_reset_exprs = wc_reset_exprs.union(self.__z3_expr_to_reg(self.between_writes_constraint, True, do_filter=True))
    if self.post_writes_constraint is not None:
      wc_reset_exprs = wc_reset_exprs.union(self.__z3_expr_to_reg(self.post_writes_constraint, True, do_filter=True))
    for s in wc_reset_exprs:
      content += '\t{}\n'.format(s)
    if self.eth_rx_desc_reg_offset is not None:
      content += '\t{0}->cur_rx_descriptor = 0;\n\t{0}->cur_tx_descriptor = 0;\n'.format(self.periph_instance_name)
    if self.timer_counter_reg_offset is not None:
      content += '\t{}->enabled = 0;\n'.format(self.periph_instance_name)
    body = body.format(
      self.register_reset_func_name,
      self.struct_name,
      self.periph_instance_name,
      content
    )
    return body
  
  def _gen_src_can_receive(self) -> str:
    if not self.has_data_reg:
      return ''
    body = \
"""
static int {0}(void *opaque) {{
\treturn 1;
}}
"""
    body = body.format(self.can_receive_func_name)
    return body

  def _gen_src_receive(self) -> str:
    if self.dma_channel_infos is not None:
      self.dma_recv_func_name = self.receive_func_name
      body = \
"""
static void {0}(struct {1} *t, uint32_t addr, uint8_t data) {{
\tint do_update = 0;
\tint channel_idx = -1;
\t{4}
\tswitch (channel_idx) {{
{2}
\t\tdefault: break;
\t}}
\tif (do_update) {{
\t\t{3}(t, channel_idx, 1);
\t\t{3}(t, channel_idx, 0);
\t}}
}}
"""
      recv_exprs = ''
      get_channel_exprs = ''
      counter = 0
      for idx in self.dma_channel_infos:
        counter += 1
        dci = self.dma_channel_infos[idx][0]
        set_irq_exprs = ''
        for e in self.__z3_expr_to_reg(dci.irq_cond, True):
          set_irq_exprs += '\t\t\t\t{}\n'.format(e)
        recv_exprs += \
'''
\t\tcase {0}: {{
\t\t\tif (t->{1}) {{
\t\t\t\tif ({2}) {{
\t\t\t\t\tcpu_physical_memory_write(t->{3}, &data, 1);
\t\t\t\t\tt->{3} += 1;
\t\t\t\t}} else {{
\t\t\t\t\tcpu_physical_memory_write(t->{4}, &data, 1);
\t\t\t\t\tt->{4} += 1;
\t\t\t\t}}
\t\t\t\tt->{1} -= 1;
\t\t\t}}
\t\t\tif (t->{1} == 0) {{
{5}
\t\t\t\tdo_update = 1;
\t\t\t}}
\t\t\tbreak;
\t\t}}
'''.format(
      idx,
      self.offset_to_reg[dci.cnt].name,
      self.__z3_expr_to_cond(dci.cond),
      self.offset_to_reg[dci.src].name,
      self.offset_to_reg[dci.dst].name,
      set_irq_exprs)
        get_channel_exprs += \
"""
if (({0}) && (t->{1} == addr || t->{2} == addr)) {{
\t\tchannel_idx = {3};
\t}} 
""".strip('\n').format(
      self.__z3_expr_to_cond(dci.enable_cond),
      self.offset_to_reg[dci.src].name,
      self.offset_to_reg[dci.dst].name,
      idx)
        if counter != len(self.dma_channel_infos):
          get_channel_exprs += ' else '
      body = body.format(
        self.receive_func_name,
        self.struct_name,
        recv_exprs,
        self.update_func_name,
        get_channel_exprs
      )
      return body
    if not self.has_data_reg:
      return ''
    body = \
"""
static void {0}(void *opaque, const uint8_t *buf, int size) {{
\t{1} *{2} = {3}(opaque);

{4}
{5}
}}
"""
    content = ''
    if self.dma_rx_enable_conds is not None and self.dma_recv_func_name is not None:
      content += \
"""
\tif ({0} && {2}->dma) {{
\t\t{1}({2}->dma, {2}->base + {3}, *buf);
\t}}
""".format(
      self.__z3_expr_to_cond(self.dma_rx_enable_conds),
      self.dma_recv_func_name,
      self.periph_instance_name,
      self.read_datareg_offset[0])
    for r_offset in self.read_datareg_offset:
      rdr = self.offset_to_reg[r_offset]
      content += '\t{}->{} = *buf;\n'.format(
        self.periph_instance_name, rdr.name
      )
    if self.read_constraint is not None:
      for s in self.__z3_expr_to_reg(self.read_constraint, True, do_filter=True):
        content += '\t{}\n'.format(s)
    do_update_expr = ''
    if self.has_update_func:
      do_update_expr += '\t{}({});'.format(self.update_func_name, self.periph_instance_name)
    body = body.format(
      self.receive_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      content,
      do_update_expr
    )
    return body

  def _gen_src_transmit(self) -> str:
    if self.dma_channel_infos is not None:
      body = \
"""
static void {0}(struct {1} *t, int channel_idx) {{
\tuint8_t data;
\tswitch (channel_idx) {{
{2}
\t\tdefault: break;
\t}}
\t{3}(t, channel_idx, 1);
\t{3}(t, channel_idx, 0);
}}
"""
      trans_exprs = ''
      for idx in self.dma_channel_infos:
        dci = self.dma_channel_infos[idx][0]
        set_irq_exprs = ''
        for e in self.__z3_expr_to_reg(dci.irq_cond, True):
          set_irq_exprs += '\t\t\t{}\n'.format(e)
        trans_exprs += \
"""
\t\tcase {0}: {{
\t\t\tif (!t->channel_enabled[{0}]) {{
\t\t\t\tbreak;
\t\t\t}}
\t\t\tif (t->{1} < 0x40000000 && t->{2} < 0x40000000) {{
\t\t\t\tfor (int i = 0; i < t->{3}; ++i) {{
\t\t\t\t\tif ({4}) {{
\t\t\t\t\t\tcpu_physical_memory_read(t->{1}, &data, 1);
\t\t\t\t\t\tcpu_physical_memory_write(t->{2}, &data, 1);
\t\t\t\t\t}} else {{
\t\t\t\t\t\tcpu_physical_memory_read(t->{2}, &data, 1);
\t\t\t\t\t\tcpu_physical_memory_write(t->{1}, &data, 1);
\t\t\t\t\t}}
\t\t\t\t\t\tt->{1} += 1;
\t\t\t\t\t\tt->{2} += 1;
\t\t\t\t}}
\t\t\t}} else {{
\t\t\t\tfor (int i = 0; i < t->{3}; ++i) {{
\t\t\t\t\tif ({4}) {{
\t\t\t\t\t\tcpu_physical_memory_read(t->{1}, &data, 1);
\t\t\t\t\t\tcpu_physical_memory_write(t->{2}, &data, 1);
\t\t\t\t\t\tt->{1} += 1;
\t\t\t\t\t}} else {{
\t\t\t\t\t\tcpu_physical_memory_read(t->{2}, &data, 1);
\t\t\t\t\t\tcpu_physical_memory_write(t->{1}, &data, 1);
\t\t\t\t\t\tt->{2} += 1;
\t\t\t\t\t}}
\t\t\t\t}}
\t\t\t}}
{5}
\t\t\tbreak;
\t\t}}
""".format(
      idx,
      self.offset_to_reg[dci.src].name,
      self.offset_to_reg[dci.dst].name,
      self.offset_to_reg[dci.cnt].name,
      self.__z3_expr_to_cond(dci.cond),
      set_irq_exprs)
      body = body.format(
        self.transmit_func_name,
        self.struct_name,
        trans_exprs,
        self.update_func_name)
      return body
    if not self.has_data_reg:
      return ''
    body = \
"""
static gboolean {0}(void *do_not_use, GIOCondition cond, void *opaque) {{
\t{1} *{2} = {3}(opaque);
\tint ret;

\t{2}->watch_tag = 0;
{4}
{5}

\tret = qemu_chr_fe_write(&({2}->chr), (uint8_t*)&({2}->{6}), 1);
\tif (ret <= 0){{
\t\t{2}->watch_tag = qemu_chr_fe_add_watch(&({2}->chr), G_IO_OUT | G_IO_HUP, {0}, {2});
\t\tif (!{2}->watch_tag) {{
\t\t\tgoto buffer_drained;
\t\t}}

\t\t return FALSE;
\t}}

buffer_drained:
{7}
{5}

\treturn FALSE;
}}
"""
    content_before_write = ''
    expr_set = set()
    
    if self.write_constraint is not None:
      expr_set = expr_set.union(self.__z3_expr_to_reg(self.write_constraint, False, do_filter=True))
    if self.between_writes_constraint is not None:
      expr_set = expr_set.union(self.__z3_expr_to_reg(self.between_writes_constraint, False, do_filter=True))
    if self.post_writes_constraint is not None:
      expr_set = expr_set.union(self.__z3_expr_to_reg(self.post_writes_constraint, False, do_filter=True))
    for s in expr_set:
      content_before_write += '\t{}\n'.format(s)
    expr_set.clear()
    content_after_write = ''
    if self.write_constraint is not None:
      expr_set = expr_set.union(self.__z3_expr_to_reg(self.write_constraint, True, do_filter=True))
    if self.between_writes_constraint is not None:
      expr_set = expr_set.union(self.__z3_expr_to_reg(self.between_writes_constraint, True, do_filter=True))
    if self.post_writes_constraint is not None:
      expr_set = expr_set.union(self.__z3_expr_to_reg(self.post_writes_constraint, True, do_filter=True))
    for s in expr_set:
      content_after_write += '\t{}\n'.format(s)
    if len(self.write_datareg_offset) == 0:
      self.has_transmit_func = False
      return ''
    self.has_transmit_func = True
    do_update_expr = ''
    if self.has_update_func:
      do_update_expr += '\t{}({});'.format(self.update_func_name, self.periph_instance_name)
    body = body.format(
      self.transmit_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      content_before_write,
      do_update_expr,
      self.offset_to_reg[self.write_datareg_offset[0]].name,
      content_after_write
    )
    return body
  
  def _gen_eth_desc_typedef(self) -> str:
    if self.eth_rx_desc_reg_offset is None:
      return ''
    body = \
"""
typedef struct {{
  uint8_t data[{0}];
}} {1};
"""
    body = body.format(self.eth_desc_size, self.eth_dma_desc_struct_name)
    return body
  
  def _gen_src_update_func(self) -> str:
    if self.dma_channel_infos is not None:
      self.has_update_func = True
      body = \
"""
static void {0}({1} *{2}, int channel_idx, int level) {{
\tqemu_set_irq({2}->irq[channel_idx], level);
}}
"""
      body = body.format(
        self.update_func_name,
        self.struct_name,
        self.periph_instance_name)
      return body
    if self.irq_constraint is None:
      return ''
    body = \
"""
static void {0}({1} *{2}) {{
\tint conditions = {3};
\tqemu_set_irq({2}->irq[0], conditions);
}}
"""
    irq_condition = self.__z3_expr_to_cond(self.irq_constraint)
    body = body.format(
      self.update_func_name,
      self.struct_name,
      self.periph_instance_name,
      irq_condition
    )
    self.has_update_func = True
    return body
  
  def _gen_eth_timer_callback_func(self) -> str:
    if self.eth_tx_desc_reg_offset is None:
      return ''
    body = \
"""
static void {5}({1} *t);

static void {0}(void *opaque) {{
	{1} *eth = ({1}*)opaque;
	{2} tx_desc;

  if (eth->timer) {{
		timer_free(eth->timer);
		eth->timer = NULL;
	}}

	if (eth->cur_tx_descriptor) {{
		cpu_physical_memory_read(eth->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
		if (!({3})) {{
			{4}(eth);
		}}
	}}

  if (!(eth->timer)) {{
		eth->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, {6}, eth);
	}}
	timer_mod(eth->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 10);
}}
"""
    body = body.format(
      self.eth_timer_callback_func_name,
      self.struct_name,
      self.eth_dma_desc_struct_name,
      self.__z3_expr_to_cond(self.eth_avail_seg_constraints, 'tx_desc'),
      self.eth_send_func_name,
      self.eth_send_func_name,
      self.eth_timer_callback_func_name
    )
    return body
  
  def _gen_timer_callback_func(self) -> str:
    if self.timer_counter_reg_offset is None:
      return ''
    body = \
"""
static void {0}(void *opaque) {{
  {1} *t = ({1}*)opaque;

  t->{2} += 1;
  if (t->{2} == t->{3}) {{
    t->{2} = 0;
    {4};
    qemu_set_irq(t->irq[0], 1);
    qemu_set_irq(t->irq[0], 0);
  }}

  if (t->enabled) {{
    timer_mod(t->timer, qemu_clock_get_{5}(QEMU_CLOCK_VIRTUAL) + 1);
  }}
}}
"""
    set_irq_expr = ''
    if self.timer_irq_constraints is not None:
      for e in self.__z3_expr_to_reg(self.timer_irq_constraints, True):
        set_irq_expr += e
    if self.time_scale is None:
      time_scale = DEFAULT_TIME_SCALE
    else:
      time_scale = self.time_scale

    body = body.format(
      self.timer_callback_func_name,
      self.struct_name,
      self.offset_to_reg[self.timer_counter_reg_offset].name,
      self.offset_to_reg[self.timer_period_reg_offset].name,
      set_irq_expr,
      time_scale
    )
    return body
  
  def _gen_eth_can_receive_func(self) -> str:
    if self.eth_tx_desc_reg_offset is None:
      return ''
    body = \
"""
static bool {0}(NetClientState* nc) {{
   return true;
}}
"""
    body = body.format(self.eth_can_receive_func_name)
    return body
  
  def _gen_eth_receive_func(self) -> str:
    if self.eth_tx_desc_reg_offset is None:
      return ''
    body = \
"""
static ssize_t {0}(NetClientState *nc, const uint8_t *buf, size_t size) {{
  {1} *t = qemu_get_nic_opaque(nc);
	{2} rx_desc, next_desc;
	uint32_t len_to_receive = size;
	uint32_t buffer_len;
	uint32_t init_rx_desc_addr = t->cur_rx_descriptor;
  uint32_t next_rx_desc_addr = 0;

	if (!init_rx_desc_addr) {{
		return -1;
	}}

	do {{
		cpu_physical_memory_read(t->cur_rx_descriptor, &rx_desc, sizeof(rx_desc));
		buffer_len = {3};
		if (buffer_len < len_to_receive) {{
			cpu_physical_memory_write({4}, buf, buffer_len);
			// receive unfinished
			len_to_receive -= buffer_len;
      {13}
			cpu_physical_memory_read(next_rx_desc_addr, &next_desc, sizeof(next_desc));
			// next available?
			if ({5}) {{
				// dont own next, make this available
				{6}
				// unset last
				{7}
				cpu_physical_memory_write(t->cur_rx_descriptor, &rx_desc, sizeof(rx_desc));
				return -1;
			}} else {{
				// make this desc available
				{6}
				// unset last
				{7}
				// set first if needed
				if (len_to_receive + buffer_len == size) {{
					// set first
					{8}
				}} else {{
					// unset first
					{9}
				}}
				// update descriptor
				cpu_physical_memory_write(t->cur_rx_descriptor, &rx_desc, sizeof(rx_desc));
        {12}
				continue;
			}}
		}} else {{
			cpu_physical_memory_write({4}, buf, len_to_receive);
			// receive finished
			// set size
			{10};
			// unset own
			{6}
			// set last
			{11}
			if (len_to_receive == size) {{
				// set first
				{8}
			}} else {{
				// unset first
				{9}
			}}
			len_to_receive = 0;
			cpu_physical_memory_write(t->cur_rx_descriptor, &rx_desc, sizeof(rx_desc));
      {12}
			break;
		}}
	}} while(true);
	return size;
}}
"""
    make_avail_exprs = self.__z3_expr_to_reg(self.eth_avail_seg_constraints, True, "rx_desc")
    make_avail_expr = ''
    for ae in make_avail_exprs:
      make_avail_expr += '{}\n'.format(ae)
    unset_last_exprs = self.__z3_expr_to_reg(self.eth_last_seg_constraints, False, "rx_desc")
    unset_last_expr = ''
    for ae in unset_last_exprs:
      unset_last_expr += '{}\n'.format(ae)
    set_last_exprs = self.__z3_expr_to_reg(self.eth_last_seg_constraints, True, "rx_desc")
    set_last_expr = ''
    for ae in set_last_exprs:
      set_last_expr += '{}\n'.format(ae)
    set_first_exprs = set()
    if self.eth_first_seg_constraints is not None:
      set_first_exprs = self.__z3_expr_to_reg(self.eth_first_seg_constraints, True, "rx_desc")
    set_first_expr = ''
    for ae in set_first_exprs:
      set_first_expr += '{}\n'.format(ae)
    unset_first_exprs = set()
    if self.eth_first_seg_constraints is not None:
      unset_first_exprs = self.__z3_expr_to_reg(self.eth_first_seg_constraints, False, "rx_desc")
    unset_first_expr = ''
    for ae in unset_first_exprs:
      unset_first_expr += '{}\n'.format(ae)

    check_next_desc_expr = ''
    get_next_get_check_expr = ''
    val_to_use = ''
    if self.eth_desc_mem_layout == 'ARRAY':
      val_to_use = 't->cur_rx_descriptor'
      check_next_desc_expr = 'if ({}) {{ t->cur_rx_descriptor = t->{}; }} else {{ t->cur_rx_descriptor = {}; }}'.format(
        self.__z3_expr_to_cond(self.eth_last_desc_constraints, "rx_desc"),
        self.offset_to_reg[self.eth_rx_desc_reg_offset].name,
        self.__eth_get_next_desc(val_to_use)
      )
      get_next_get_check_expr = 'if ({}) {{ next_rx_desc_addr = t->{}; }} else {{ next_rx_desc_addr = {}; }}'.format(
        self.__z3_expr_to_cond(self.eth_last_desc_constraints, "rx_desc"),
        self.offset_to_reg[self.eth_rx_desc_reg_offset].name,
        self.__eth_get_next_desc(val_to_use)
      )
    elif self.eth_desc_mem_layout == 'RINGBUF':
      val_to_use = 'rx_desc'
      check_next_desc_expr = 't->cur_rx_descriptor = {};'.format(
        self.__eth_get_next_desc(val_to_use))
      get_next_get_check_expr = 'next_rx_desc_addr = {};'.format(
        self.__eth_get_next_desc(val_to_use))
      
    body = body.format(
      self.eth_receive_func_name,
      self.struct_name,
      self.eth_dma_desc_struct_name,
      self.__eth_get_eth_desc_rx_buf_len('rx_desc'),
      self.__get_field("rx_desc", self.eth_desc_buf),
      self.__z3_expr_to_cond(self.eth_avail_seg_constraints, "next_desc"),
      make_avail_expr,
      unset_last_expr,
      set_first_expr,
      unset_first_expr,
      self.__set_field('rx_desc', self.eth_desc_rx_frame_len, '(size + 4)'),
      set_last_expr,
      check_next_desc_expr,
      get_next_get_check_expr
    )
    return body
  
  def _gen_eth_send_func(self) -> str:
    if self.eth_tx_desc_reg_offset is None:
      return ''
    if self.eth_first_seg_constraints is not None:
      body = \
"""
static void {0}({1} *t) {{
	uint32_t init_tx_desc_addr = t->cur_tx_descriptor;
	{2} tx_desc;
	int frame_len = 0;
	uint32_t start_tx_desc_addr = 0;
	uint32_t end_tx_desc_addr = 0;
  uint32_t next_tx_desc_addr = 0;
	uint8_t *buf;
	uint8_t *trans_buf;

	if (t->cur_tx_descriptor) {{
		do {{
			cpu_physical_memory_read(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
			if (!({3})) {{
				if (({4}) && ({5})) {{
					// last and first
					frame_len += {6};
					end_tx_desc_addr = t->cur_tx_descriptor;
					start_tx_desc_addr = t->cur_tx_descriptor;
					break;
				}} else if ({4}) {{
					// last
					frame_len += {6};
					end_tx_desc_addr = t->cur_tx_descriptor;
					break;
				}} else if ({5}) {{
					// first
					frame_len += {6};
					start_tx_desc_addr = t->cur_tx_descriptor;
				}} else {{
					// inter
					frame_len += {6};
				}}
			}}
      {7}
			t->cur_tx_descriptor = next_tx_desc_addr;
		}} while (next_tx_desc_addr != init_tx_desc_addr);

		if (start_tx_desc_addr && end_tx_desc_addr && frame_len) {{
			assert(frame_len > 14);
			buf = g_malloc(frame_len);
			trans_buf = buf;
			init_tx_desc_addr = start_tx_desc_addr;
			t->cur_tx_descriptor = start_tx_desc_addr;
			do {{
				cpu_physical_memory_read(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
				if (!({3})) {{
					// transfer it
					cpu_physical_memory_read({8}, trans_buf, {6});
					frame_len -= ({6});
					if (frame_len <=0) {{
						// done!
						trans_buf += ({6});
						break;
					}} else {{
						trans_buf += ({6});
					}}
					{9}
					cpu_physical_memory_write(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
          {7}
					t->cur_tx_descriptor = next_tx_desc_addr;
				}} else {{
					// dont own
					free(buf);
					return;
				}}
			}} while (next_tx_desc_addr != init_tx_desc_addr);
			assert(frame_len <= 0);
			frame_len = trans_buf - buf;
			qemu_send_packet(qemu_get_queue(t->nic), buf, frame_len);
			free(buf);
			{9}
			cpu_physical_memory_write(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
      {7}
			t->cur_tx_descriptor = next_tx_desc_addr;
		}}
	}}
}}
"""
      make_avail_exprs = self.__z3_expr_to_reg(self.eth_avail_seg_constraints, True, "tx_desc")
      make_avail_expr = ''
      for ae in make_avail_exprs:
        make_avail_expr += '{}\n'.format(ae)

      get_next_desc_expr = ''
      if self.eth_desc_mem_layout == 'RINGBUF':
        get_next_desc_expr = 'next_tx_desc_addr = {};'.format(
          self.__eth_get_next_desc('tx_desc'))
      elif self.eth_desc_mem_layout == 'ARRAY':
        get_next_desc_expr = 'if ({}) {{ next_tx_desc_addr = t->{}; }} else {{ next_tx_desc_addr = {}; }}'.format(
          self.__z3_expr_to_cond(self.eth_last_desc_constraints, "tx_desc"),
          self.offset_to_reg[self.eth_tx_desc_reg_offset].name,
          self.__eth_get_next_desc('t->cur_tx_descriptor')
        )

      body = body.format(
        self.eth_send_func_name,
        self.struct_name,
        self.eth_dma_desc_struct_name,
        self.__z3_expr_to_cond(self.eth_avail_seg_constraints, "tx_desc"),
        self.__z3_expr_to_cond(self.eth_last_seg_constraints, "tx_desc"),
        self.__z3_expr_to_cond(self.eth_first_seg_constraints, "tx_desc"),
        self.__get_field("tx_desc", self.eth_desc_tx_buf_len),
        get_next_desc_expr,
        self.__get_field("tx_desc", self.eth_desc_buf),
        make_avail_expr,
        self.eth_timer_callback_func_name
      )
    else:
      body = \
"""
static void {0}({1} *t) {{
	uint32_t init_tx_desc_addr = t->cur_tx_descriptor;
	{2} tx_desc;
	int frame_len = 0;
	uint32_t start_tx_desc_addr = 0;
	uint32_t end_tx_desc_addr = 0;
  uint32_t next_tx_desc_addr = 0;
	uint8_t *buf;
	uint8_t *trans_buf;

	if (t->cur_tx_descriptor) {{
		do {{
			cpu_physical_memory_read(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
			if (!({3})) {{
        if (!start_tx_desc_addr) {{
          start_tx_desc_addr = init_tx_desc_addr;
        }}
				if ({4}) {{
					// last
					frame_len += {5};
					end_tx_desc_addr = t->cur_tx_descriptor;
					break;
				}} else {{
					// first or inter
					frame_len += {5};
				}}
			}}
      {6}
			t->cur_tx_descriptor = next_tx_desc_addr;
		}} while (next_tx_desc_addr != init_tx_desc_addr);

		if (start_tx_desc_addr && end_tx_desc_addr && frame_len) {{
			assert(frame_len > 14);
			buf = g_malloc(frame_len);
			trans_buf = buf;
			init_tx_desc_addr = start_tx_desc_addr;
			t->cur_tx_descriptor = start_tx_desc_addr;
			do {{
				cpu_physical_memory_read(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
				if (!({3})) {{
					// transfer it
					cpu_physical_memory_read({7}, trans_buf, {5});
					frame_len -= ({5});
					if (frame_len <=0) {{
						// done!
						trans_buf += ({5});
						break;
					}} else {{
						trans_buf += ({5});
					}}
					{8}
					cpu_physical_memory_write(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
          {6}
					t->cur_tx_descriptor = next_tx_desc_addr;
				}} else {{
					// dont own
					free(buf);
					return;
				}}
			}} while (next_tx_desc_addr != init_tx_desc_addr);
			assert(frame_len <= 0);
			frame_len = trans_buf - buf;
			qemu_send_packet(qemu_get_queue(t->nic), buf, frame_len);
			free(buf);
			{8}
			cpu_physical_memory_write(t->cur_tx_descriptor, &tx_desc, sizeof(tx_desc));
      {6}
			t->cur_tx_descriptor = next_tx_desc_addr;
		}}
	}}
}}
"""
      make_avail_exprs = self.__z3_expr_to_reg(self.eth_avail_seg_constraints, True, "tx_desc")
      make_avail_expr = ''
      for ae in make_avail_exprs:
        make_avail_expr += '{}\n'.format(ae)

      get_next_desc_expr = ''
      if self.eth_desc_mem_layout == 'RINGBUF':
        get_next_desc_expr = 'next_tx_desc_addr = {};'.format(
          self.__eth_get_next_desc('tx_desc'))
      elif self.eth_desc_mem_layout == 'ARRAY':
        get_next_desc_expr = 'if ({}) {{ next_tx_desc_addr = t->{}; }} else {{ next_tx_desc_addr = {}; }}'.format(
          self.__z3_expr_to_cond(self.eth_last_desc_constraints, "tx_desc"),
          self.offset_to_reg[self.eth_tx_desc_reg_offset].name,
          self.__eth_get_next_desc('t->cur_tx_descriptor')
        )

      body = body.format(
        self.eth_send_func_name,
        self.struct_name,
        self.eth_dma_desc_struct_name,
        self.__z3_expr_to_cond(self.eth_avail_seg_constraints, "tx_desc"),
        self.__z3_expr_to_cond(self.eth_last_seg_constraints, "tx_desc"),
        self.__get_field("tx_desc", self.eth_desc_tx_buf_len),
        get_next_desc_expr,
        self.__get_field("tx_desc", self.eth_desc_buf),
        make_avail_expr,
        self.eth_timer_callback_func_name
      )
    return body
  
  def _gen_src_read_func(self) -> str:
    body = \
"""
static uint64_t {0}(void *opaque, hwaddr offset, unsigned size) {{
\t{1} *{2} = {3}(opaque);
\tuint64_t ret;

\tswitch (offset) {{
{4}
\t\tdefault:
\t\t\tqemu_log_mask(LOG_GUEST_ERROR, \"{5} {6} read: bad offset %x\\n\", (int)offset);
\t\t\tret = 0;
\t\t\tbreak;
\t}}
\treturn ret;
}}
"""
    content = ''
    visited_offset = set()
    for r in self.regs:
      can_read = False
      if r._access is not None:
        if 'read' in r._access:
          can_read = True
      else:
        fields: List[SVDField] = r._fields
        for f in fields:
          if f.access:
            if 'read' in f.access:
              can_read = True
              break
          else:
            can_read = True
            break
      if not can_read:
        continue
      if r.address_offset not in visited_offset:
        visited_offset.add(r.address_offset)
      else:
        continue
      if self.all_in_one:
        content += '\t\tcase A_{}_{}:\n'.format(self.name_upper, r.name)
      else:
        content += '\t\tcase A_{}:\n'.format(r.name)
      content += '\t\t\tret = {}->{};\n'.format(
        self.periph_instance_name, r.name
      )
      if r.address_offset in self.read_datareg_offset:
        # 1. unset the condition:
        if self.read_constraint is not None:
          for s in self.__z3_expr_to_reg(self.read_constraint, False, do_filter=True):
            content += '\t\t\t{}\n'.format(s)
        # 2. accept input:
        content += '\t\t\tqemu_chr_fe_accept_input(&({}->chr));\n'.format(
          self.periph_instance_name
        )
        # 3. update irq:
        if self.has_update_func:
          content += '\t\t\t{}({});\n'.format(
            self.update_func_name, self.periph_instance_name
          )
      content += '\t\t\tbreak;\n'
    body = body.format(
      self.read_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      content,
      self.prefix_upper,
      self.name_upper
    )
    return body
  
  def _gen_src_write_func(self) -> str:
    body = \
"""
static void {0}(void *opaque, hwaddr offset, uint64_t value, unsigned size) {{
\t{1} *{2} = {3}(opaque);

\tswitch (offset) {{
{4}
\t\tdefault:
\t\t\tqemu_log_mask(LOG_GUEST_ERROR, \"{5} {6} write: bad offset %x\\n\", (int)offset);
\t\t\tbreak;
\t}}
}}
"""
    content = ''
    visited_offset = set()
    for r in self.regs:
      can_write = False
      if r._access is not None:
        if 'write' in r._access:
          can_write = True
      else:
        fields: List[SVDField] = r._fields
        for f in fields:
          if f.access:
            if 'write' in f.access:
              can_write = True
              break
          else:
            can_write = True
            break
      if not can_write:
        continue
      if r.address_offset not in visited_offset:
        visited_offset.add(r.address_offset)
      else:
        continue
      if self.all_in_one:
        content += '\t\tcase A_{}_{}:\n'.format(self.name_upper, r.name)
      else:
        content += '\t\tcase A_{}:\n'.format(r.name)
      if r.address_offset in self.data_related_reg_offset and CR_REGEX.fullmatch(r.name) is None:
        # these registers as considered as status registers, as a result,
        # bits of these registers should only be set by hardware
        content += '\t\t\t{}->{} &= value;\n'.format(
          self.periph_instance_name, r.name
        )
      else:
        content += '\t\t\t{}->{} = value;\n'.format(
          self.periph_instance_name, r.name
        )
      do_irq_update = False
      if r.address_offset in self.write_datareg_offset:
        content += '\t\t\t{}(NULL, G_IO_OUT, {});\n'.format(
          self.transmit_func_name, self.periph_instance_name
        )
      if r.address_offset in self.reg_offset_to_cond_actions:
        for pair in self.reg_offset_to_cond_actions[r.address_offset]:
          for ro in pair[2]:
            if ro in self.irq_reg_offset:
              do_irq_update = True
          c_cond = self.__z3_expr_to_cond(pair[0], "value")
          c_action = self.__z3_expr_to_reg(pair[1], True)
          if len(c_action) > 0:
            if len(c_cond) > 0:
              content += '\t\t\tif ({}) {{\n'.format(c_cond)
              for ca in c_action:
                content += '\t\t\t\t{}\n'.format(ca)
              content += '\t\t\t}\n'
            else:
              for ca in c_action:
                content += '\t\t\t{}\n'.format(ca)
          
      if r.address_offset in self.irq_reg_offset:
        do_irq_update = True

      if do_irq_update and self.has_update_func and self.dma_channel_infos is None:
        content += '\t\t\t{}({});\n'.format(
          self.update_func_name, self.periph_instance_name
        )
      
      if r.address_offset == self.eth_rx_desc_reg_offset:
        content += '\t\t\t{}->cur_rx_descriptor = value;\n'.format(
          self.periph_instance_name)
      if r.address_offset == self.eth_tx_desc_reg_offset:
        content += '\t\t\t{}->cur_tx_descriptor = value;\n'.format(
          self.periph_instance_name)
      if self.timer_counter_reg_offset is not None:
        enable_reg = self.__collect_related_regs(self.timer_enable_constraints).pop()
        disable_reg = self.__collect_related_regs(self.timer_disable_constraints).pop()
        if self.time_scale is None:
          time_scale = DEFAULT_TIME_SCALE
        else:
          time_scale = self.time_scale
        if r.address_offset == enable_reg:
          content += '\t\t\tif ({}) {{\n'.format(self.__z3_expr_to_cond(self.timer_enable_constraints))
          content += '\t\t\t\t{}->enabled = 1;\n'.format(self.periph_instance_name)
          content += '\t\t\t\ttimer_mod({}->timer, qemu_clock_get_{}(QEMU_CLOCK_VIRTUAL) + 1);\n'.format(self.periph_instance_name, time_scale)
          content += '\t\t\t}\n'
        if r.address_offset == disable_reg:
          content += '\t\t\tif ({}) {{\n'.format(self.__z3_expr_to_cond(self.timer_disable_constraints))
          content += '\t\t\t\t{}->enabled = 0;\n'.format(self.periph_instance_name)
          content += '\t\t\t\ttimer_free({}->timer);\n'.format(self.periph_instance_name)
          content += '\t\t\t\t{0}->timer = timer_new(QEMU_CLOCK_VIRTUAL, SCALE_{1}, {2}, {0});\n'.format(
            self.periph_instance_name, time_scale.upper(),
            self.timer_callback_func_name)
          content += '\t\t\t}\n'
      if self.dma_channel_infos is not None:
        for idx in self.dma_channel_infos:
          dci = self.dma_channel_infos[idx][0]
          enable_reg = self.__collect_related_regs(dci.enable_cond).pop()
          disable_reg = self.__collect_related_regs(dci.disable_cond).pop()
          if r.address_offset == enable_reg:
            content += \
'''
\t\t\tif (!{4}->channel_enabled[{6}] && {0}) {{
\t\t\t\t{4}->channel_enabled[{6}] = 1;
\t\t\t\tif ({4}->{1} < 0x40000000 && {4}->{2} < 0x40000000) {{
\t\t\t\t\t{3}({4}, {6});
\t\t\t\t}} else {{
\t\t\t\t\tif ({5}) {{
\t\t\t\t\t\tif ({4}->{1} < 0x40000000) {{
\t\t\t\t\t\t\t{3}({4}, {6});
\t\t\t\t\t\t}}
\t\t\t\t\t}} else {{
\t\t\t\t\t\tif ({4}->{2} < 0x40000000) {{
\t\t\t\t\t\t\t{3}({4}, {6});
\t\t\t\t\t\t}}
\t\t\t\t\t}}
\t\t\t\t}}
\t\t\t}}
'''.format(
      self.__z3_expr_to_cond(dci.enable_cond),
      self.offset_to_reg[dci.src].name,
      self.offset_to_reg[dci.dst].name,
      self.transmit_func_name,
      self.periph_instance_name,
      self.__z3_expr_to_cond(dci.cond),
      idx)
          if r.address_offset == disable_reg:
            content += \
"""
\t\t\tif ({0}) {{
\t\t\t\t{1}->channel_enabled[{2}] = 0;
\t\t\t}}
""".format(
      self.__z3_expr_to_cond(dci.disable_cond),
      self.periph_instance_name,
      idx)
      content += '\t\t\tbreak;\n'
    body = body.format(
      self.write_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      content,
      self.prefix_upper,
      self.name_upper
    )
    return body

  def _gen_src_ops_struct(self) -> str:
    body = \
"""
static const MemoryRegionOps {0} = {{
\t.read = {1},
\t.write = {2},
\t.endianness = DEVICE_LITTLE_ENDIAN
}};
"""
    body = body.format(
      self.ops_struct_name, self.read_func_name, self.write_func_name
    )
    return body

  def _gen_eth_info_struct(self) -> str:
    if self.eth_rx_desc_reg_offset is None:
      return ''
    body = \
"""
static NetClientInfo {0} = {{
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = {1},
    .receive = {2},
}};
"""
    body = body.format(
      self.eth_info_struct_name,
      self.eth_can_receive_func_name,
      self.eth_receive_func_name)
    return body

  def _gen_src_instance_init_func(self) -> str:
    body = \
"""
static void {0}(Object *obj) {{
\tSysBusDevice *sbd = SYS_BUS_DEVICE(obj);
\t{1} *{2} = {3}(obj);
\tmemory_region_init_io(&({2}->iomem), obj, &{4}, {2}, \"{5}\", {6});
\tsysbus_init_mmio(sbd, &({2}->iomem));
{7}
}}
"""
    content = ''
    num_irq = 0
    for p in self.target:
      if p._interrupts:
        num_irq = len(p._interrupts)
    if num_irq > 0:
      content += '\tfor (int i = 0; i < {}; ++i) {{\n'.format(num_irq)
      content += '\t\tsysbus_init_irq(sbd, &({}->irq[i]));\n'.format(
        self.periph_instance_name
      )
      content += '\t}\n'
    body = body.format(
      self.init_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      self.ops_struct_name,
      self.symbol_name,
      self.periph_size_def,
      content
    )
    return body
  
  def _gen_src_realize_func(self) -> str:
    body = \
"""
static void {0}(DeviceState *dev, Error **errp) {{
{1}
}}
"""
    content = ''
    if self.has_data_reg:
      content += '\t{} *{} = {}(dev);\n\n'.format(
        self.struct_name, self.periph_instance_name, self.full_name_upper
      )
      tmp = "\tqemu_chr_fe_set_handlers(\n"       \
            "\t\t&({0}->chr), {1}, {2},\n"        \
            "\t\tNULL, NULL, {0}, NULL, true);\n"
      content += tmp.format(
        self.periph_instance_name,
        self.can_receive_func_name,
        self.receive_func_name
      )
    elif self.eth_rx_desc_reg_offset is not None:
      content += '\t{} *{} = {}(dev);\n\n'.format(
        self.struct_name, self.periph_instance_name, self.full_name_upper
      )
      tmp = "\tqemu_macaddr_default_if_unset(&{0}->conf.macaddr);\n"   \
            "\t{0}->nic = qemu_new_nic(\n"  \
            "\t\t&{1}, &{0}->conf,\n"       \
            "\t\tobject_get_typename(OBJECT(dev)), dev->id, {0});\n"  \
            "\tqemu_format_nic_info_str(qemu_get_queue({0}->nic), {0}->conf.macaddr.a);\n" \
            "\t{0}->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, {2}, {0});"  \
            "\ttimer_mod({0}->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 10);"
      content += tmp.format(
        self.periph_instance_name,
        self.eth_info_struct_name,
        self.eth_timer_callback_func_name
      )
    elif self.timer_counter_reg_offset is not None:
      if self.time_scale is None:
        time_scale = DEFAULT_TIME_SCALE
      else:
        time_scale = self.time_scale
      content += '\t{0} *{1} = {2}(dev);\n'.format(
        self.struct_name, self.periph_instance_name, self.full_name_upper)
      content += '\t{0}->timer = timer_new(QEMU_CLOCK_VIRTUAL, SCALE_{1}, {2}, {0});\n'.format(
        self.periph_instance_name, time_scale.upper(), self.timer_callback_func_name)
    elif self.dma_rx_enable_conds is not None:
      content += '\t{0}->dma = NULL;\n'.format(self.periph_instance_name)
    else:
      content += '\treturn;\n'
    body = body.format(self.realize_func_name, content)
    return body
  
  def _gen_src_reset_enter_func(self) -> str:
    body = \
"""
static void {0}(Object *obj, ResetType type) {{
\t{1} *{2} = {3}(obj);
\t{4}({2});
}}
"""
    body = body.format(
      self.reset_enter_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      self.register_reset_func_name
    )
    return body
  
  def _gen_src_vmstate_struct(self) -> str:
    body = \
"""
static const VMStateDescription {0} = {{
\t.name = \"{1}\",
\t.version_id = 0,
\t.minimum_version_id = 0,
\t.fields = (VMStateField[]) {{
{2}
\t\tVMSTATE_END_OF_LIST()
\t}}
}};
"""
    content = ''
    for r in self.regs:
      content += '\t\tVMSTATE_UINT{}({}, {}),\n'.format(
        r._size, r.name, self.struct_name
      )
    body = body.format(self.vmstate_struct_name, self.symbol_name, content)
    return body

  def _gen_src_properties_struct(self) -> str:
    if self.eth_rx_desc_reg_offset is not None:
      body = \
"""
static Property {0}[] = {{
\tDEFINE_NIC_PROPERTIES({1}, conf),
\tDEFINE_PROP_END_OF_LIST()
}};
"""
      body = body.format(self.properties_struct_name, self.struct_name)
      return body
    if not self.has_data_reg:
      return ''
    body = \
"""
static Property {0}[] = {{
\tDEFINE_PROP_CHR(\"chardev\", {1}, chr),
\tDEFINE_PROP_END_OF_LIST()
}};
"""
    body = body.format(self.properties_struct_name, self.struct_name)
    return body

  def _gen_src_class_init_func(self) -> str:
    body = \
"""
static void {0}(ObjectClass *oc, void *data) {{
\tDeviceClass *dc = DEVICE_CLASS(oc);
\tResettableClass *rc = RESETTABLE_CLASS(oc);
\tdc->vmsd = &{1};
\tdc->realize = {2};
\trc->phases.enter = {3};
{4}
}}
"""
    content = ''
    if self.has_data_reg or self.eth_rx_desc_reg_offset is not None:
      content += '\tdevice_class_set_props(dc, {});\n'.format(
        self.properties_struct_name
      )
    body = body.format(
      self.class_init_func_name,
      self.vmstate_struct_name,
      self.realize_func_name,
      self.reset_enter_func_name,
      content
    )
    return body
  
  def _gen_src_type_info_struct(self) -> str:
    body = \
"""
static const TypeInfo {0} = {{
\t.name = {1},
\t.parent = TYPE_SYS_BUS_DEVICE,
\t.instance_size = sizeof({2}),
\t.instance_init = {3},
\t.class_init = {4},
}};
"""
    body = body.format(
      self.info_struct_name,
      self.type_name,
      self.struct_name,
      self.init_func_name,
      self.class_init_func_name
    )
    return body
  
  def _gen_src_register_type_func(self) -> str:
    body = \
"""
static void {0}(void) {{
\ttype_register_static(&{1});
}}
"""
    body = body.format(self.register_types_func_name, self.info_struct_name)
    return body
  
  def _gen_src_type_init(self) -> str:
    body = \
"""
type_init({0});
"""
    body = body.format(self.register_types_func_name)
    return body
  
  def _gen_board_include(self) -> str:
    body = ''
    for i in self.board_include:
      body += '#include \"{}\"\n'.format(i)
    body += '\n'
    return body
  
  def _gen_board_defs(self) -> str:
    body = \
"""
#define {0} MACHINE_TYPE_NAME(\"{1}\")
OBJECT_DECLARE_TYPE({2}, {3}, {4})
"""
    body = body.format(
      self.machine_type_def,
      self.machine_name,
      self.machine_state_struct_name,
      self.machine_class_struct_name,
      self.machine_type_conv
    )
    return body
  
  def _gen_board_struct(self) -> str:
    body = \
"""
struct {0} {{
\tMachineClass parent;
}};

struct {1} {{
\tMachineState parent;
\tARMv7MState armv7m;
}};
"""
    body = body.format(
      self.machine_class_struct_name, self.machine_state_struct_name
    )
    return body
  
  def _gen_board_peripheral_setup_func(self) -> str:
    body = \
"""
static void {0}(MachineState *machine) {{
\t{1} *sms = {2}(machine);
{3}
}}
"""
    content = ''
    cnt = 0
    for bp in self.board_peripherals:
      ins = []
      if 'instance' in bp:
        ins = bp['instance']
      else:
        ins.append(bp['kind'])
      bp_kind = bp['kind']
      periph_struct_name = '{}{}'.format(self.prefix_upper, bp_kind.upper())
      periph_type_def = 'TYPE_{}_{}'.format(self.prefix_upper, bp_kind).upper()
      for i in ins:
        is_pattern = False
        if '*' in i or '?' in i or '[' in i:
          is_pattern = True
        is_eth = False
        if 'ethernet' in i.lower() or 'enet' in i.lower():
          is_eth = True
        if is_eth:
          content += '\tqemu_check_nic_model(&nd_table[0], "{}");\n'.format(
            self.machine_name
          )
        ptr_name = 'p{}'.format(cnt)
        cnt += 1
        content += '\t{0} *{1} = g_new({0}, 1);\n'.format(
          periph_struct_name, ptr_name
        )
        if is_pattern:
          content += '\tobject_initialize_child(OBJECT(sms), \"{}\", {}, {});\n'.format(
            bp_kind, ptr_name, periph_type_def
          )
        else:
          content += '\tobject_initialize_child(OBJECT(sms), \"{}\", {}, {});\n'.format(
            i, ptr_name, periph_type_def
          )
        if bp_kind in self.data_reg_periph:
          content += '\tqdev_prop_set_chr(DEVICE({0}), "chardev", qemu_chr_new("soc-{1}", "chardev:{1}", NULL));\n'.format(
            ptr_name, i.lower()
          )
        if is_eth:
          content += '\tqdev_set_nic_properties(DEVICE({}), &nd_table[0]);\n'.format(ptr_name)
        content += '\tsysbus_realize(SYS_BUS_DEVICE({}), &error_fatal);\n'.format(ptr_name)
        if not is_pattern:
          i_irq: List[SVDInterrupt] = self.name_to_peripheral[i]._interrupts
        else:
          i_irq = []
          p_bases = []
          for p in self.device.peripherals:
            if fnmatch.fnmatch(p.name, i):
              p_bases.append(self.__get_peripheral_base(p))
              if p._interrupts:
                i_irq += p._interrupts
          p_bases = sorted(p_bases)
        if not is_pattern:
          content += '\t{}->base = {};\n'.format(
            ptr_name, hex(self.__get_peripheral_base(self.name_to_peripheral[i])))
        else:
          content += '\t{}->base = {};\n'.format(ptr_name, hex(p_bases[0]))
        if i_irq is not None:
          for irq_idx in range(len(i_irq)):
            content += '\tsysbus_connect_irq(SYS_BUS_DEVICE({}), {}, qdev_get_gpio_in(DEVICE(&(sms->armv7m)), {}));\n'.format(
              ptr_name, irq_idx, i_irq[irq_idx].value
            )
        if not is_pattern:
          content += '\tsysbus_mmio_map(SYS_BUS_DEVICE({}), 0, {});\n\n'.format(
            ptr_name, hex(self.__get_peripheral_base(self.name_to_peripheral[i]))
          )
        else:
          content += '\tsysbus_mmio_map(SYS_BUS_DEVICE({}), 0, {});\n\n'.format(
            ptr_name, hex(p_bases[0])
          )
    body = body.format(
      self.board_periph_init_func_name,
      self.machine_state_struct_name,
      self.machine_type_conv,
      content
    )
    return body

  def _gen_board_common_setup_func(self) -> str:
    body = \
"""
static void {0}(MachineState *machine) {{
\t{1} *sms = {2}(machine);
\tMemoryRegion *sysmem = get_system_memory();
\tMemoryRegion *mem;
\tClock *cpuclk = clock_new(OBJECT(sms), \"SYSCLK\");
\tclock_set_hz(cpuclk, {3});
\tClock *refclk = clock_new(OBJECT(sms), \"REFCLK\");
\tclock_set_hz(refclk, {3});

{4}
\tobject_initialize_child(OBJECT(sms), "armv7m", &(sms->armv7m), TYPE_ARMV7M);
\tqdev_prop_set_uint32(DEVICE(&(sms->armv7m)),"num-irq", {5});
\tqdev_prop_set_string(DEVICE(&(sms->armv7m)), "cpu-type", machine->cpu_type);
\tqdev_prop_set_bit(DEVICE(&(sms->armv7m)), "enable-bitband", {8});
\tqdev_connect_clock_in(DEVICE(&(sms->armv7m)), "cpuclk", cpuclk);
\tqdev_connect_clock_in(DEVICE(&(sms->armv7m)), "refclk", refclk);
\tqdev_prop_set_uint32(DEVICE(&(sms->armv7m)), "init-nsvtor", {6});
\tobject_property_set_link(OBJECT(&sms->armv7m), "memory", OBJECT(sysmem), &error_abort);
\tsysbus_realize(SYS_BUS_DEVICE(&sms->armv7m), &error_fatal);

\t{7}(machine);

\tarmv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename, {9}, {10});
}}
"""
    content = ''
    for m in self.memory_regions:
      content += '\tmem = g_new(MemoryRegion, 1);\n'
      mem_type = m['type']
      if mem_type == 'flash':
        self.flash_size = m['size']
        self.flash_base = m['base']
      if mem_type == 'ram':
        content += \
          '\tmemory_region_init_ram(mem, NULL, \"{}\", {}, &error_fatal);\n'.format(
          m['name'], hex(m['size'])
        )
      elif mem_type == 'rom' or mem_type == 'flash':
        content += \
          '\tmemory_region_init_rom(mem, NULL, \"{}\", {}, &error_fatal);\n'.format(
          m['name'], hex(m['size'])
        )
      else:
        print("unrecognized mem type {}, abort".format(mem_type))
        sys.exit(9)
      content += '\tmemory_region_add_subregion(sysmem, {}, mem);\n\n'.format(
        hex(m['base'])
      )
    if self.flash_size is None:
      print("Must specify one flash memory region")
      sys.exit(10)
    body = body.format(
      self.board_common_init_func_name,
      self.machine_state_struct_name,
      self.machine_type_conv,
      self.clk_freq,
      content,
      self.num_irq,
      hex(self.init_vtor),
      self.board_periph_init_func_name,
      "true" if self.board_bitband else "false",
      hex(self.flash_base),
      hex(self.flash_size)
    )
    return body

  def _gen_board_class_init_func(self) -> str:
    body = \
"""
static void {0}(ObjectClass *oc, void *data) {{
\tMachineClass *mc = MACHINE_CLASS(oc);
\tmc->desc = \"{1}\";
\tmc->init = {2};
\tmc->max_cpus = 1;
\tmc->default_cpus = 1;
\tmc->default_cpu_type = ARM_CPU_TYPE_NAME(\"{3}\");
}}
"""
    body = body.format(
      self.board_class_init_func_name,
      self.machine_name,
      self.board_common_init_func_name,
      self.cpu_type_name
    )
    return body

  def _gen_board_info_struct(self) -> str:
    body = \
"""
static const TypeInfo {0} = {{
\t.name = {1},
\t.parent = TYPE_MACHINE,
\t.instance_size = sizeof({2}),
\t.class_size = sizeof({3}),
\t.class_init = {4}
}};
"""
    body = body.format(
      self.board_info_struct_name,
      self.machine_type_def,
      self.machine_state_struct_name,
      self.machine_class_struct_name,
      self.board_class_init_func_name
    )
    return body

  def _gen_board_init_func(self) -> str:
    body = \
"""
static void {0}(void) {{
\ttype_register_static(&{1});
}}
"""
    body = body.format(self.board_init_func_name, self.board_info_struct_name);
    return body

  def _gen_board_type_init(self) -> str:
    body = \
"""
type_init({0});
"""
    body = body.format(self.board_init_func_name);
    return body
  
  def _gen_header(self) -> str:
    body = \
"""
#ifndef {0}
#define {0}
{1}
#endif
"""
    content = ''
    if not self.all_in_one:
      content += self._gen_header_include()
    content += self._gen_header_qom_def()
    content += self._gen_header_struct()

    if not self.all_in_one:
      body = body.format(self.header_def, content)
      return body
    else:
      return content
  
  def _gen_source(self) -> str:
    generator_list = [
      self._gen_src_include,
      self._gen_src_macros,
      self._gen_eth_desc_typedef,
      self._gen_src_update_func,
      self._gen_eth_timer_callback_func,
      self._gen_timer_callback_func,
      self._gen_eth_can_receive_func,
      self._gen_eth_receive_func,
      self._gen_eth_send_func,
      self._gen_src_can_receive,
      self._gen_src_receive,
      self._gen_src_transmit,
      self._gen_src_register_reset_func,
      self._gen_src_read_func,
      self._gen_src_write_func,
      self._gen_src_ops_struct,
      self._gen_eth_info_struct,
      self._gen_src_instance_init_func,
      self._gen_src_realize_func,
      self._gen_src_reset_enter_func,
      self._gen_src_vmstate_struct,
      self._gen_src_properties_struct,
      self._gen_src_class_init_func,
      self._gen_src_type_info_struct,
      self._gen_src_register_type_func,
      self._gen_src_type_init
    ]
    if self.all_in_one:
      generator_list.pop(0)
    body = ''
    for gen_fn in generator_list:
      body += gen_fn()
    return body
  
  def _gen_board(self) -> str:
    generator_list = [
      self._gen_board_include,
      self._gen_board_defs,
      self._gen_board_struct,
      self._gen_board_peripheral_setup_func,
      self._gen_board_common_setup_func,
      self._gen_board_class_init_func,
      self._gen_board_info_struct,
      self._gen_board_init_func,
      self._gen_board_type_init
    ]
    if self.all_in_one:
      generator_list.pop(0)
    body = ''
    for g in generator_list:
      body += g()
    return body
  
  def __run_perry(self, p):
    target = p['target']
    config_file_path = Path(self.config_file)
    target_bc = str(config_file_path.parent / p['target-bitcode'])
    target_struct = p['target-struct']
    out_file = p['constraint_file']
    additional_bc = []
    if 'additional-bitcode' in p:
      for abc in p['additional-bitcode']:
        additional_bc.append(str(config_file_path.parent / abc))
    target_periph_base = []
    target_periph_end = []
    for ppp in self.device.peripherals:
      if fnmatch.fnmatch(ppp.name, target):
        target_periph_base.append(self.__get_peripheral_base(ppp))
        target_periph_end.append(self.__get_peripheral_end(ppp))
    target_periph_base = sorted(target_periph_base)
    target_periph_end = sorted(target_periph_end, reverse=True)
    addon_cmd = [
      "--target-periph-struct={}".format(target_struct),
      "--target-periph-address={}".format(
        hex(target_periph_base[0])
      ),
      "--target-periph-size={}".format(hex(target_periph_end[0] - target_periph_base[0])),
      "--perry-out-file={}".format(out_file),
    ]

    if 'partial-concretize' in p:
      if p['partial-concretize']:
        addon_cmd.append("--perry-concretize-all=false")

    bc_to_include = set(self.shared_bitcode)
    for abc in additional_bc:
      bc_to_include.add(abc)

    for bc in bc_to_include:
      if bc != target_bc:
        addon_cmd.append("--link-llvm-lib={}".format(bc))
    
    for hk_pair in PERIPH_HOOKS:
      for periph_prefix in hk_pair[0]:
        if target.startswith(periph_prefix):
          for hk in hk_pair[1]:
            addon_cmd.append("--perry-function-hook={}".format(hk))

    addon_cmd.append(target_bc)
    subprocess.run(self.perry_common_cmd + addon_cmd, stdout=sys.stdout)
  
  def dump_peripheral(self, target=None):
    if target is None:
      target = self.peripheral_results.keys()
    root_dir = None
    if self.output_dir is not None:
      root_dir = Path(self.output_dir)
    for t in target:
      the_tuple = self.peripheral_results[t]
      if not self.all_in_one:
        file_prefix = the_tuple[0]
        header_file_name = file_prefix + '.h'
        source_file_name = file_prefix + '.c'
        if root_dir is None:
          print("// {}".format(header_file_name))
          print(the_tuple[1])
          print("// {}".format(source_file_name))
          print(the_tuple[2])
        else:
          p = root_dir / header_file_name
          p.write_text(the_tuple[1])
          p = root_dir / source_file_name
          p.write_text(the_tuple[2])
      else:
        self.all_in_one_content += (the_tuple[1] + the_tuple[2])
  
  def dump_board(self):
    if self.board_result is None:
      print('Board is not synthesized yet, cannot dump')
      return
    if not self.all_in_one:
      root_dir = None
      if self.output_dir is not None:
        root_dir = Path(self.output_dir)
      out_file_name = self.machine_name + '.c'
      if root_dir is None:
        print("// {}".format(out_file_name))
        print(self.board_result)
      else:
        p = root_dir / out_file_name
        p.write_text(self.board_result)
    else:
      self.all_in_one_content += self.board_result
  
  def dump(self):
    self.dump_peripheral()
    self.dump_board()
    if self.all_in_one:
      all_header = ''
      for h in self.all_in_one_include:
        all_header += '#include \"{}\"\n'.format(h)
      all_header += "\n";
      all_content = all_header + self.all_in_one_content
      root_dir = None
      if self.output_dir is not None:
        root_dir = Path(self.output_dir)
      out_file_name = self.machine_name + '.c'
      if root_dir is None:
        print(all_content)
      else:
        p = root_dir / out_file_name
        p.write_text(all_content)

  def run_peripherals(self):
    if self.peripheral_workload is None:
      return
    for p in self.peripheral_workload:
      p_target = p['target']
      p_name = None
      if 'kind' in p:
        p_name = p['kind']
      # should we use perry to infer peripheral model?
      use_perry = False
      if 'use-perry' in p:
        if p['use-perry'] is True:
          use_perry = True
      # check constraint file
      run_perry = False
      p_constraint_file = None
      if 'constraint_file' in p:
        p_constraint_file = p['constraint_file']
        cs_file_path = Path(p_constraint_file)
        if not cs_file_path.exists():
          run_perry = True
      # if we should use perry, and the constraint file is not presented, run perry
      if use_perry and run_perry:
        self.__run_perry(p)
      self.__setup_peripheral_ctx(p_target, p_name, p_constraint_file)
      if self.has_data_reg:
        the_name = p_target if p_name is None else p_name
        self.data_reg_periph.add(the_name)
      hd = self._gen_header()
      src = self._gen_source()
      self.peripheral_results[p_target] = (self.symbol_name, hd, src)

  def run_board(self):
    if self.board_config is None:
      return
    self.board_result = self._gen_board()
  
  def run(self):
    self.run_peripherals()
    self.run_board()