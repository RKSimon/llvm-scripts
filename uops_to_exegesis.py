#!/usr/bin/env python3

from ast import Continue
import xml.etree.ElementTree as ET

# TODO: SNB/IVB
def get_cpu_details(cpu):
   details = {
      "BNL":  ["BNL", "bonnell", "AtomPort", 2],
      "SNB":  ["SNB", "sandybridge", "SBPort", 6],
      "IVB":  ["IVB", "ivybridge", "SBPort", 6],
      "HSW":  ["HSW", "haswell", "HWPort", 8],
      "BDW":  ["BDW", "broadwell", "BWPort", 8],
      "SKL":  ["SKL", "skylake", "SKLPort", 8],
      "SKX":  ["SKX", "skylake-avx512", "SKXPort", 8],
      "CNL":  ["CNL", "cannonlake", "SKXPort", 8],
      "CLX":  ["CLX", "cascadelake", "SKXPort", 8],
      "ICL":  ["ICL", "icelake-server", "ICXPort", 10],
      "RKL":  ["RKL", "rocketlake", "ICXPort", 10],
      "TGL":  ["TGL", "tigerlake", "ICXPort", 10],
      "ADL":  ["ADL-P", "alderlake", "ADLPPort", 12],
      "ZEN+": ["ZEN+", "znver1", "ZnFPU", 4],
      "ZEN1": ["ZEN+", "znver1", "ZnFPU", 4],
      "ZEN2": ["ZEN2", "znver2", "Zn2FPU", 4],
      "ZEN3": ["ZEN3", "znver3", "Zn3FP", 4],
      "ZEN4": ["ZEN4", "znver4", "Zn4FP", 4]
      }
   return details.get(cpu)

def print_cpu_uops_yaml(cpu):
   root = ET.parse('instructions.xml')

   [cpuname, cpumodel, portprefix, numports] = get_cpu_details(cpu)

   for instrNode in root.iter('instruction'):
      if instrNode.attrib['extension'] not in ['MMX', 'SSE', 'SSE2', 'SSE3', 'SSSE3', 'SSE4', 'AVX', 'AVX2', 'PCLMULQDQ', 'VPCLMULQDQ']: # 'SSE4a', 'FMA'
         continue
      if any(x in instrNode.attrib['isa-set'] for x in ['FP16']):
         continue

      asm = instrNode.attrib['asm']
      sig = ''
      args = ''

      # Ignore uops.info custom instruction variants
      if asm.find("PCMPESTRIQ") != -1 or asm.find("PCMPISTRIQ") != -1 or asm.find("PCMPESTRMQ") != -1 or asm.find("PCMPISTRMQ") != -1:
        continue

      # TODO: Broken instructions (don't follow the standard naming convention)
      if asm.find("EXTRACT") != -1 or asm.find("INSERT") != -1:
        continue
      if asm.find("RCPS") != -1 or asm.find("SQRTS") != -1 or asm.find("ROUNDS") != -1:
        continue
      if asm.find("PEXTR") != -1 or asm.find("PINSR") != -1 or asm.find("PREFETCH") != -1:
        continue
      if asm.find("BROADCAST") != -1 or asm.find("F128") != -1 or asm.find("I128") != -1 or asm.find("LDDQU") != -1 or asm.find("MXCSR") != -1:
        continue
      if asm.find("CRC") != -1:
        continue
      if asm.find("CVT") != -1:
        continue
      if asm.find("MOV") != -1:
        if asm.find("SX") == -1 and asm.find("ZX") == -1 and asm.find("DUP") == -1:
          continue

      archs = instrNode.iter('architecture')
      if not any(x.attrib['name'] == cpuname for x in archs):
        continue;

      ismmx = instrNode.attrib['category'] in ['MMX'] or instrNode.attrib['extension'] in ['MMX']
      issse = instrNode.attrib['extension'] in ['SSE', 'SSE2', 'SSE3', 'SSSE3', 'SSE4', 'SSE4a']
      isopmask = instrNode.attrib.get('mask', '0') == '1'
      iszeroing = instrNode.attrib.get('zeroing', '0') == '1'

      isload = asm.startswith("{load}")
      asm = asm.removeprefix("{load}").lstrip()

      isstore = asm.startswith("{store}")
      asm = asm.removeprefix("{store}").lstrip()

      if asm.find("MOV") != -1:
        if asm.find("PMOVSX") != -1 or asm.find("PMOVZX") != -1 or asm.find("DUP") != -1:
          sig += 'r'

      # Cleanup signature to match LLVM opnames
      if asm.find("ABS") != -1 or asm.find("HMINPOS") != -1:
        sig += 'r'

      first = True
      fail = False
      for operandNode in instrNode.iter('operand'):
        operandIdx = int(operandNode.attrib['idx'])

        if operandNode.attrib.get('suppressed', '0') == '1':
          continue;

        if operandNode.attrib['type'] == 'reg':
          registers = operandNode.text.split(',')
          register = registers[min(operandIdx, len(registers)-1)]
          args += register + ' '
          if first and (ismmx or issse):
            args += register + ' '
        elif operandNode.attrib['type'] == 'mem':
          args += 'RDI i_0x1 %noreg '
        elif operandNode.attrib['type'] == 'imm':
          args += 'i_0x1 '

        if operandNode.attrib.get('r', '0') == '0':
          continue;

        if first:
          if asm.find("POPCNT") != -1:
            sig += operandNode.attrib.get('width', '')
            sig += 'r'
          elif operandNode.attrib.get('width', '128') == '256':
            asm += 'Y'

        if operandNode.attrib['type'] == 'reg':
          sig += 'r'
        elif operandNode.attrib['type'] == 'imm':
          sig += 'i'
        elif operandNode.attrib['type'] == 'mem':
          sig += 'm'
        else:
          fail = True
          continue;

        first = False

      if fail:
         continue;

      if ismmx:
         asm = "MMX_" + asm

      # SSE BLENDV xmm0 hack
      if asm.startswith("BLENDV") or asm.startswith("PBLENDV"):
         sig += '0'

      portlist = None
      uops = None
      for archNode in instrNode.iter('architecture'):
         if archNode.attrib['name'] != cpuname:
            continue;

         for measureNode in archNode.iter('measurement'):
            uops = float(measureNode.attrib['uops'])
            if measureNode.attrib.get('ports', None) is not None:
               portlist = measureNode.attrib['ports']

      if portlist is None or uops is None:
         fail = True;

      if fail:
         continue;

      # ports="1*p01+1*p23"
      # TODO: Compute Idealized Resource Pressure
      ports = dict()
      for x in portlist.split('+'):
        [scale,group] = x.split('*')
        group = group.removeprefix('FP').removeprefix('p')
        for p in list(group):
           ports[int(p)] = ports.get(int(p), 0.0) + (float(scale) / float(len(group)))

      args = args.lstrip().rstrip()

      print(f"---")
      print(f"mode:            uops")
      print(f"key:")
      print(f"  instructions:")
      print(f"    - '{asm}{sig} {args}'")
      print(f"  config:          ''")
      print(f"  register_initial_values:")
      print(f"    - 'XMM0=0x0'")
      print(f"    - 'MXCSR=0x0'")
      print(f"cpu_name:        {cpumodel}")
      print(f"llvm_triple:     x86_64-unknown-linux-gnu")
      print(f"num_repetitions: 10000")
      print(f"measurements:")
      for p in range(numports):
         print(f"  - {{ key: {portprefix}{p}, value: {ports.get(p, 0.0)}, per_snippet_value: {ports.get(p, 0.0)} }}")
      print(f"  - {{ key: NumMicroOps, value: {uops}, per_snippet_value: {uops} }}")
      print(f"error:           ''")
      print(f"info:            instruction is serial, repeating a random one.")
      print(f"assembled_snippet: B0004883EC08C7042400000000C7442404000000009D37373737C3")
      print(f"...")

def main():
   print_cpu_uops_yaml('HSW')

if __name__ == "__main__":
    main()
