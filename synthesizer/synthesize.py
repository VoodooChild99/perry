import argparse
import sys
from pathlib import Path
from typing import List

from cmsis_svd.parser import SVDParser, SVDDevice, SVDPeripheral, SVDInterrupt
from prettytable import PrettyTable
from synthesizer import Synthesizer

def list_peripherals(svd_file: str):
  svd_parser = SVDParser.for_xml_file(svd_file)
  device: SVDDevice = svd_parser.get_device()
  p_table = PrettyTable()
  p_table.field_names = [
    "Base Address", "Size", "Name", "Interrupt", "Derived From"
  ]
  p_table.sortby = "Base Address"
  peripherals: List[SVDPeripheral] = device.peripherals
  for p in peripherals:
    irqs = []
    irq_list: List[SVDInterrupt] = p._interrupts
    if irq_list is not None:
      for irq in irq_list:
        irqs.append(irq.value)
    derived_from = p.get_derived_from()
    if derived_from is None:
      entry = [
        "0x%08x" % p._base_address,
        hex(p._address_block.size),
        p.name,
        irqs,
        ''
      ]
    else:
      entry = [
        "0x%08x" % p._base_address,
        hex(derived_from._address_block.size),
        p.name,
        irqs,
        derived_from.name
      ]
    p_table.add_row(entry)
  print(p_table)

def main(args):
  if args.list:
    list_peripherals(args.svd_file)
  
  if args.config_file:
    s = Synthesizer(args.config_file, args.output_dir)
    try:
      s.run()
      s.dump()
    except KeyboardInterrupt:
      print("[*] Interrupted by user, dumping current result...")
      s.dump()

def __to_absolute_path(path: str) -> str:
  p = Path(path)
  if not p.exists():
    raise argparse.ArgumentTypeError('path {} does not exist'.format(p))
  return str(p.resolve())

def __svd_file_required() -> bool:
  conds = ['-l', '--list']
  for c in conds:
    if c in sys.argv:
      return True
  return False

if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser(
    description="synthesize QEMU-compatible peripheral drivers from SVD files "
                "and collected constraints"
  )
  arg_parser.add_argument(
    '-f', '--svd-file',
    type=__to_absolute_path,
    metavar='SVD-PATH',
    required=__svd_file_required(),
    help="Path to the SVD file"
  )
  arg_parser.add_argument(
    '-o', '--output-dir',
    type=__to_absolute_path,
    metavar='OUTPUT-DIR',
    required=False,
    help="Where to write the generated model. (default to stdout)"
  )
  arg_parser.add_argument(
    '-l', '--list',
    required=False,
    action='store_true',
    help="List Peripherals in the SVD File"
  )
  arg_parser.add_argument(
    '-c', '--config-file',
    required=False,
    type=__to_absolute_path,
    metavar='CONFIG-FILE',
    help='YAML-format config file for the synthesizer'
  )

  main(arg_parser.parse_args())