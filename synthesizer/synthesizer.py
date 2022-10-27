import json
import sys
import re
import yaml
import subprocess

from pathlib import Path
from z3 import *
from cmsis_svd.parser import (
  SVDParser,
  SVDDevice,
  SVDPeripheral,
  SVDRegister,
  SVDField,
  SVDInterrupt
)
from typing import List, Mapping, Set, Tuple

class Synthesizer:
  def __init__(self, config_file: str, output_dir: str) -> None:
    self.config_file = config_file
    self.output_dir = output_dir
    self.__parse_yaml()
    self.__setup_perry_cmdline()
    self.peripheral_results: Mapping[str, Tuple[str, str, str]] = {}
    self.board_result = None

  def __get_peripheral_base(self, p: SVDPeripheral) -> int:
    p_derived_from = p.get_derived_from()
    p_p = p
    if p_derived_from is not None:
      p_p = p_derived_from
    first_reg: SVDRegister = p_p.registers[0]
    return first_reg.address_offset + p._base_address
    
  
  def __get_peripheral_size(self, p: SVDPeripheral) -> int:
    p_derived_from = p.get_derived_from()
    if p_derived_from is not None:
      p = p_derived_from
    last_reg: SVDRegister = p.registers[-1]
    return last_reg.address_offset + (last_reg._size >> 3)
  
  def __parse_ar_archive(self, path: str) -> List[str]:
    contained_files = subprocess.check_output(['ar', '-t', path]).decode().strip()
    return contained_files.split('\n')
  
  def __extract_from_ar_archive(self, ar_path: str, name: str):
    os.system("ar -x {} {} --output={}".format(
      ar_path, name, Path(ar_path).parent
    ))

  def __setup_perry_cmdline(self):
    self.perry_common_cmd = [self.perry_path]

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

    # try resolve conflict
    all_ranges = []
    for p in peripherals:
      _p_base = self.__get_peripheral_base(p)
      _p_size = self.__get_peripheral_size(p)
      all_ranges.append((_p_base, _p_base + _p_size - 1))
    for p in self.additional_peripheral:
      all_ranges.append((p['base'], p['base'] + p['size'] - 1))
    
    all_ranges = sorted(all_ranges, key=lambda x:x[0])
    ranges_no_conflict = []
    prev_range = all_ranges[0]
    ranges_no_conflict.append(prev_range)
    for i in range(1, len(all_ranges)):
      prev_end = prev_range[1]
      cur_begin = all_ranges[i][0]
      cur_end = all_ranges[i][1]
      if prev_end >= cur_begin:
        if cur_end <= prev_end:
          print("merging peripheral range [{}, {}] and [{}, {}]".format(
            hex(prev_range[0]), hex(prev_range[1]),
            hex(all_ranges[i][0]), hex(all_ranges[i][1])))
        else:
          print("failed to merge overlapping peripheral range [{}, {}] and [{}, {}]".format(
            hex(prev_range[0]), hex(prev_range[1]),
            hex(all_ranges[i][0]), hex(all_ranges[i][1])))
          exit(10)
      else:
        # no conflict
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
    
    for ef in self.exclude_function:
      self.perry_common_cmd.append("--exclude-function-list={}".format(ef))
    
    for incf in self.include_function:
      self.perry_common_cmd.append("--include-function-list={}".format(incf))

    self.perry_common_cmd += [
      "--arm-cpu-version={}".format(self.cpu_type_name),
      "--write-no-tests=true",
      # "--search=dfs",
      "--max-solver-time=10s",
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
    ############
    ### Misc ###
    ############
    # set target
    peripherals: List[SVDPeripheral] = self.device.peripherals
    self.target = None
    for p in peripherals:
      if p.get_derived_from() is None and p.name == target:
        self.target = p
        break
    if self.target is None:
      print("Failed to locate {}".format(target))
      sys.exit(11)
    self.offset_to_reg = {}
    if self.target is not None:
      regs: List[SVDRegister] = self.target.registers
      # idx = 0
      for r in regs:
        # if r._size != 0x20:
        #   print("In {}, the size of register {} is not 32 bits, "
        #         "which is not supported by now.".format(target, r.name))
        #   sys.exit(2)
        self.offset_to_reg[r.address_offset] = r
        # if (r.address_offset >> 2) != idx and self.has_data_reg:
        #   print("In {}, the index of register {} is not continuous, "
        #         "which is not supported by now.".format(target, r.name))
        #   sys.exit(3)
        # idx += 1
      self.regs = regs
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
    self.header_include = [
      'hw/sysbus.h',
      'qom/object.h'
    ]
    self.chardev_include = [
      'chardev/char-fe.h'
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
      '{}.h'.format(self.symbol_name),
      'hw/qdev-properties-system.h',
      'exec/cpu-common.h'
    ]
  
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
    board_include = [
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
    for p in self.board_peripherals:
      board_include.append('{}-{}.h'.format(self.prefix, p['kind'].lower()))
    self.board_include = board_include
  
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
  
  def __collect_related_regs(self, expr: ExprRef) \
        -> Tuple[Set[int], Mapping[str, SVDRegister]]:
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
        assert(left.decl().kind() == Z3_OP_EXTRACT)
        assert(is_bv_value(right))
        sym_name = left.arg(0).decl().name()
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
  
  def __z3_expr_to_cond(self, expr: ExprRef) -> str:
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
        assert(left.decl().kind() == Z3_OP_EXTRACT)
        assert(is_bv_value(right))
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
        sym_name: str = left.arg(0).decl().name()
        if sym_name not in self.sym_name_to_reg:
          reg_offset = int(self.sym_name_regex.match(sym_name).groups()[1])
          # reg_idx = (reg_idx >> 2)
          self.sym_name_to_reg[sym_name] = self.offset_to_reg[reg_offset]
        target_reg = self.sym_name_to_reg[sym_name]
        extract_high, extract_low = left.params()
        mask = 0
        while extract_low <= extract_high:
          mask |= (1 << extract_low)
          extract_low += 1
        right_val = right.as_long()
        if right_val == 1:
          tmp = '({}->{} & {})'.format(
            self.periph_instance_name, target_reg.name, hex(mask)
          )
        else:
          assert(right_val == 0)
          tmp = '(!({}->{} & {}))'.format(
            self.periph_instance_name, target_reg.name, hex(mask)
          )
        sub_expr.append(tmp)
    assert(len(sub_expr) == 1)
    return sub_expr.pop()

  def __z3_expr_to_reg(self, expr: ExprRef, is_set: bool) -> List[str]:
    # For now, we only support AND, NOT, EQ. 
    # Note that the AND expr must not be a sub-expr of NOT. Otherwise we may
    # have multiple options, and we need to ask the solver to workout a proper
    # model. But empirically these situations rarely happen.
    WL: List[ExprRef] = []
    WL.append(expr)
    set_expr: List[ExprRef] = []
    reg_ops: List[str] = []
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
      else:
        print("Not supported z3 expr {}, ignore".format(cur))
        # sys.exit(8)
        return []
    for e in set_expr:
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
      assert(left.decl().kind() == Z3_OP_EXTRACT)
      assert(is_bv_value(right))
      sym_name = left.arg(0).decl().name()
      if sym_name not in self.sym_name_to_reg:
        reg_offset = int(self.sym_name_regex.match(sym_name).groups()[1])
        # reg_idx = (reg_idx >> 2)
        self.sym_name_to_reg[sym_name] = self.offset_to_reg[reg_offset]
      target_reg = self.sym_name_to_reg[sym_name]
      right_val = right.as_long()
      assert(right_val == 1)
      extract_high, extract_low = left.params()
      mask = 0
      while extract_low <= extract_high:
        mask |= (1 << extract_low)
        extract_low += 1
      body = '{}->{}'.format(self.periph_instance_name, target_reg.name)
      real_set = is_set ^ needs_negate
      if real_set:
        body += ' |= {};'.format(hex(mask))
      else:
        body += ' &= (~({}));'.format(hex(mask))
      reg_ops.append(body)
    return reg_ops

  def _gen_header_include(self) -> str:
    body = ''
    for item in self.header_include:
      body += '#include "{}"\n'.format(item)
    if self.has_data_reg:
      for item in self.chardev_include:
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
    if self.target._interrupts:
      num_irq = len(self.target._interrupts)
    if num_irq > 0:
      content += '\t/* irqs */\n'
      content += '\tqemu_irq irq[{}];\n\n'.format(num_irq)
    # registers
    content += '\t/*registers*/\n'
    for r in self.regs:
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
      self.periph_size_def, hex(self.__get_peripheral_size(self.target))
    )
    for r in self.regs:
      body += 'REG{}({}, {})\n'.format(r._size, r.name, hex(r.address_offset))
      fields: List[SVDField] = r._fields
      for f in fields:
        body += '\tFIELD({}, {}, {}, {})\n'.format(
          r.name, f.name, f.bit_offset, f.bit_width
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
      content += '\t{}->{} = {};\n'.format(
        self.periph_instance_name, r.name, hex(r._reset_value)
      )
    # reset write conditions
    if self.write_constraint is not None:
      for s in self.__z3_expr_to_reg(self.write_constraint, False):
        content += '\t{}\n'.format(s)
    if self.between_writes_constraint is not None:
      for s in self.__z3_expr_to_reg(self.between_writes_constraint, False):
        content += '\t{}\n'.format(s)
    if self.post_writes_constraint is not None:
      for s in self.__z3_expr_to_reg(self.post_writes_constraint, False):
        content += '\t{}\n'.format(s)
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
    if not self.has_data_reg:
      return ''
    body = \
"""
static void {0}(void *opaque, const uint8_t *buf, int size) {{
\t{1} *{2} = {3}(opaque);

{4}
\t{5}({2});
}}
"""
    content = ''
    for r_offset in self.read_datareg_offset:
      rdr = self.offset_to_reg[r_offset]
      content += '\t{}->{} = *buf;\n'.format(
        self.periph_instance_name, rdr.name
      )
    if self.read_constraint is not None:
      for s in self.__z3_expr_to_reg(self.read_constraint, True):
        content += '\t{}\n'.format(s)
    body = body.format(
      self.receive_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      content,
      self.update_func_name
    )
    return body

  def _gen_src_transmit(self) -> str:
    if not self.has_data_reg:
      return ''
    body = \
"""
static gboolean {0}(void *do_not_use, GIOCondition cond, void *opaque) {{
\t{1} *{2} = {3}(opaque);
\tint ret;

\t{2}->watch_tag = 0;
{4}
\t{5}({2});

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
\t{5}({2});

\treturn FALSE;
}}
"""
    content_before_write = ''
    if self.write_constraint is not None:
      for s in self.__z3_expr_to_reg(self.write_constraint, False):
        content_before_write += '\t{}\n'.format(s)
    if self.between_writes_constraint is not None:
      for s in self.__z3_expr_to_reg(self.between_writes_constraint, False):
        content_before_write += '\t{}\n'.format(s)
    if self.post_writes_constraint is not None:
      for s in self.__z3_expr_to_reg(self.post_writes_constraint, False):
        content_before_write += '\t{}\n'.format(s)
    content_after_write = ''
    if self.write_constraint is not None:
      for s in self.__z3_expr_to_reg(self.write_constraint, True):
        content_after_write += '\t{}\n'.format(s)
    if self.between_writes_constraint is not None:
      for s in self.__z3_expr_to_reg(self.between_writes_constraint, True):
        content_after_write += '\t{}\n'.format(s)
    if self.post_writes_constraint is not None:
      for s in self.__z3_expr_to_reg(self.post_writes_constraint, True):
        content_after_write += '\t{}\n'.format(s)
    assert(len(self.write_datareg_offset) == 1)
    body = body.format(
      self.transmit_func_name,
      self.struct_name,
      self.periph_instance_name,
      self.full_name_upper,
      content_before_write,
      self.update_func_name,
      self.offset_to_reg[self.write_datareg_offset[0]].name,
      content_after_write
    )
    return body
  
  def _gen_src_update_func(self) -> str:
    if not self.has_data_reg:
      return ''
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
          if 'read' in f.access:
            can_read = True
            break
      if not can_read:
        continue
      if r.address_offset not in visited_offset:
        visited_offset.add(r.address_offset)
      else:
        continue
      content += '\t\tcase A_{}:\n'.format(r.name)
      content += '\t\t\tret = {}->{};\n'.format(
        self.periph_instance_name, r.name
      )
      if r.address_offset in self.read_datareg_offset:
        # 1. unset the condition:
        if self.read_constraint is not None:
          for s in self.__z3_expr_to_reg(self.read_constraint, False):
            content += '\t\t\t{}\n'.format(s)
        # 2. accept input:
        content += '\t\t\tqemu_chr_fe_accept_input(&({}->chr));\n'.format(
          self.periph_instance_name
        )
        # 3. update irq:
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
          if 'write' in f.access:
            can_write = True
            break
      if not can_write:
        continue
      if r.address_offset not in visited_offset:
        visited_offset.add(r.address_offset)
      else:
        continue
      content += '\t\tcase A_{}:\n'.format(r.name)
      if r.address_offset in self.data_related_reg_offset:
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
          c_cond = self.__z3_expr_to_cond(pair[0])
          c_action = self.__z3_expr_to_reg(pair[1], True)
          if len(c_action) > 0:
            content += '\t\t\tif ({}) {{\n'.format(c_cond)
            for ca in c_action:
              content += '\t\t\t\t{}\n'.format(ca)
            content += '\t\t\t}\n'
          
      if r.address_offset in self.irq_reg_offset:
        do_irq_update = True

      if do_irq_update:
        content += '\t\t\t{}({});\n'.format(
          self.update_func_name, self.periph_instance_name
        )
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
    if self.target._interrupts:
      num_irq = len(self.target._interrupts)
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
    if self.has_data_reg:
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
      periph_type_def = 'TYPE_{}_{}'.format(self.prefix_upper, bp_kind)
      for i in ins:
        ptr_name = 'p{}'.format(cnt)
        cnt += 1
        content += '\t{0} *{1} = g_new({0}, 1);\n'.format(
          periph_struct_name, ptr_name
        )
        content += '\tobject_initialize_child(OBJECT(sms), \"{}\", {}, {});\n'.format(
          i, ptr_name, periph_type_def
        )
        content += '\tsysbus_realize(SYS_BUS_DEVICE({}), &error_fatal);\n'.format(ptr_name)
        i_irq: List[SVDInterrupt] = self.name_to_peripheral[i]._interrupts
        if i_irq is not None:
          for irq_idx in range(len(i_irq)):
            content += '\tsysbus_connect_irq(SYS_BUS_DEVICE({}), {}, qdev_get_gpio_in(DEVICE(&(sms->armv7m)), {}));\n'.format(
              ptr_name, irq_idx, i_irq[irq_idx].value
            )
        content += '\tsysbus_mmio_map(SYS_BUS_DEVICE({}), 0, {});\n\n'.format(
          ptr_name, hex(self.__get_peripheral_base(self.name_to_peripheral[i]))
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
\tqdev_prop_set_bit(DEVICE(&(sms->armv7m)), "enable-bitband", {9});
\tqdev_connect_clock_in(DEVICE(&(sms->armv7m)), "cpuclk", cpuclk);
\tqdev_connect_clock_in(DEVICE(&(sms->armv7m)), "refclk", refclk);
\tqdev_prop_set_uint32(DEVICE(&(sms->armv7m)), "init-nsvtor", {6});
\tobject_property_set_link(OBJECT(&sms->armv7m), "memory", OBJECT(sysmem), &error_abort);
\tsysbus_realize(SYS_BUS_DEVICE(&sms->armv7m), &error_fatal);

\t{7}(machine);

\tarmv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename, {8});
}}
"""
    content = ''
    for m in self.memory_regions:
      content += '\tmem = g_new(MemoryRegion, 1);\n'
      mem_type = m['type']
      if mem_type == 'flash':
        self.flash_size = m['size']
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
      hex(self.flash_size),
      "true" if self.board_bitband else "false"
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
    content += self._gen_header_include()
    content += self._gen_header_qom_def()
    content += self._gen_header_struct()

    body = body.format(self.header_def, content)
    return body
  
  def _gen_source(self) -> str:
    generator_list = [
      self._gen_src_include,
      self._gen_src_macros,
      self._gen_src_update_func,
      self._gen_src_can_receive,
      self._gen_src_receive,
      self._gen_src_transmit,
      self._gen_src_register_reset_func,
      self._gen_src_read_func,
      self._gen_src_write_func,
      self._gen_src_ops_struct,
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
    addon_cmd = [
      "--target-periph-struct={}".format(target_struct),
      "--target-periph-address={}".format(
        hex(self.__get_peripheral_base(self.name_to_peripheral[target]))
      ),
      "--perry-out-file={}".format(out_file),
    ]

    bc_to_include = set(self.shared_bitcode)
    for abc in additional_bc:
      bc_to_include.add(abc)

    for bc in bc_to_include:
      if bc != target_bc:
        addon_cmd.append("--link-llvm-lib={}".format(bc))
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
  
  def dump_board(self):
    if self.board_result is None:
      print('Board is not synthesized yet, cannot dump')
      return
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
  
  def dump(self):
    self.dump_peripheral()
    self.dump_board()

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