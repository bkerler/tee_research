#MCLF TlApi Func Auto-Renamer
#@author B.Kerler info@revskills.de
#@category ARM
#@keybinding
#@menupath
#@toolbar

#Licensed under MIT license
#Ghidra plugin. Use MCLF Loader, let autoanalysis finish, then run this script for fun

import logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
import ghidra.program.model.data.StringDataType as StringDataType
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

tlapilist = {
    0x1:"tlApiGetVersion",
    0x2:"tlApiGetMobicoreVersion",
    0x4:"tlApiExit",
    0x6:"tlApiWaitNotification",
    0x5:"tlApiLogvPrintf",
    0x7:"tlApiNotify",
    0x8:"tlApi_callDriver",
    0x9:"tlApiWrapObjectExt",
    0xA:"tlApiUnwrapObjectExt",
    0xB:"tlApiGetSuid",
    0xC:"tlApi_callDriverEx",
    0xD:"tlApiCrAbort",
    0xE:"tlApiRandomGenerateData",
    0xF:"tlApiGenerateKeyPair",
    0x10:"tlApiCipherInitWithData",
    0x11:"tlApiCipherUpdate",
    0x12:"tlApiCipherDoFinal",
    0x13:"tlApiSignatureInitWithData",
    0x14:"tlApiSignatureUpdate",
    0x15:"tlApiSignatureSign",
    0x16:"tlApiSignatureVerify",
    0x17:"tlApiMessageDigestInitWithData",
    0x18:"tlApiMessageDigestUpdate",
    0x19:"tlApiMessageDigestDoFinal",
    0x1A:"tlApiGetVirtMemType",
    0x1B:"tlApiDeriveKey",
    0x1C:"tlApiMalloc",
    0x1D:"tlApiRealloc",
    0x1E:"tlApiFree",
    0x55:"tlApiEndorse",
    0x56:"tlApiTuiGetScreenInfo",
    0x57:"tlApiTuiOpenSession",
    0x58:"tlApiTuiCloseSession",
    0x59:"tlApiTuiSetImage",
    0x5A:"tlApiTuiGetTouchEvent",
    0x5D:"tlApiDrmOpenSession",
    0x5E:"tlApiDrmCloseSession",
    0x5F:"tlApiDrmCheckLink",
    0x62:"tlApiGetSecureTimestamp",
    0x64:"tlApiAddEntropy",
    0x65:"tlApiCreateHeap",
    0x68:"TEE_TBase_CloseSessions",
    0x69:"TEE_TBase_TakeIdentity",
    0x6A:"TEE_TBase_RevertIdentity",
    0x6B:"TEE_TBase_DeleteAllObjects"
}

def getstring(insn,field):
    opRefs = insn.getOperandReferences(field)
    for o in opRefs:
        if o.getReferenceType().isData():
            string = getStringAtAddr(o.getToAddress())
            return string

def getcaller(ea):
    refs = getReferencesTo(ea)
    pea=[]
    for r in refs:
	pea.append(r.getFromAddress())
    return pea

def get_tlapi_num(addr):
    inst = getInstructionAt(addr)
    for i in range(0,10):
        inst = getInstructionAfter(inst)
        if inst.getMnemonicString()=="mov":
            if inst.getOpObjects(0)[0].toString()=="r0":
               r0=inst.getOpObjects(1)[0]
               return r0.getValue()

def setfuncname(ea,name):
    func = fm.getFunctionContaining(ea)
    if func!=None:
        func.setName(name,SourceType.USER_DEFINED)

def makefunc(ea,name=None):
    removeFunctionAt(ea)
    removeSymbol(ea, name)
    clearListing(ea)
    createFunction(ea, name)
    disassemble(ea)
    
def getStringAtAddr(addr):
    """Get string at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()
        if isinstance(dt, StringDataType):
            return str(data.getValue())
    return None

def tlapicallback(ea):
    val=get_tlapi_num(ea)
    if val in tlapilist:
       name=tlapilist[val]
       print("[TlApi Call] %08X:%s" % (ea.getOffset(), name))
       setfuncname(ea,name)
       ma=fm.getFunctionContaining(ea).getEntryPoint()
       if val==1:
          setfuncname(getcaller(ma)[0],"tlMain")
       elif val==5:
          pea=getcaller(ma)[0]
          setfuncname(pea,"tlApiLogPrintf")
          pea=fm.getFunctionContaining(pea).getEntryPoint()
          for sea in getcaller(pea):
              mea=getInstructionAt(sea)
              for pos in range(0,0x100):
                  mea=getInstructionBefore(mea)
                  ppop=mea.getMnemonicString()
                  if ppop in ("movw"):
                     r0=mea.getOpObjects(1)[0]
                     rtype=mea.getOperandRefType(1)
                     if rtype.isData():
                        v=r0.toString()
                        if v[:2]=="0x":
                           pstring=getStringAtAddr(toAddr(int(v,16)))
                           #MTK here be lions
                           if pstring is not None:
                               if ("[" in pstring) and ("]" in pstring):
                                   idx=pstring.index("[")
                                   if idx==0:
                                      funcname=pstring[idx+1:]
                                      funcname=funcname[:funcname.index("]")]
                                      if not funcname.lower() in ("key","key1","ki"):
                                         if not " " in funcname:
                                            fea=fm.getFunctionContaining(sea)
                                            if fea is not None:
                                               ep=fea.getEntryPoint()
                                               print("0x%08x:%s" % (ep.getOffset(),funcname))
                                               setfuncname(ep,funcname)
                        break 

def findAll(pattern, mask):
    mem = currentProgram.getMemory()
    foundAll = []
    for block in mem.getBlocks():
        start = block.getStart()
        end = block.getEnd()
        done = False
        found = 0
        while found != None and not monitor.isCancelled():
            found = mem.findBytes(start, end, pattern, mask, True, monitor)
            if found != None:
                foundAll.append(found)
                start = found.add(1)
    return foundAll

for addr in getcaller(toAddr(0x108C)):
    tlapicallback(addr)

big = currentProgram.getMemory().isBigEndian()

'''
opcodes=[b"\x2D\xE9\xFF",b"\x2D\xE9\xF0",b"\xF0\xB5",b"\x00\xB5","\x30\xB5"]
for opcode in opcodes:
    opaddrs=findAll(opcode,None)
    for ea in opaddrs:
        makefunc(ea)
'''
        
#Here be Samsungs (s6, s7)
opcodes=[b"\x0F\xB4\x1C\xB5\x0C\x00\x07\xAA\x00\x90\x01\xD0"]
for opcode in opcodes:
    opaddrs=findAll(opcode,None)
    for ea in opaddrs:
        setfuncname(ea,"LOG_I")
        break

#Here be Samsungs (s6, s7)
opcodes=[b"\x42\x1C\x02\xE0\x10\xF8\x01\x1B\x69\xB1"]
for opcode in opcodes:
    opaddrs=findAll(opcode,None)
    for ea in opaddrs:
        setfuncname(ea,"strlen")
        xrefs=getcaller(ea)
        for xref in xrefs:
            #print(xref)
            pea=getInstructionAt(xref)
            nea=getInstructionAfter(pea)
            ppop=nea.getMnemonicString()
            if ppop in ("ldr"):
                opr=nea.getOpObjects(0)[0]
                if opr.toString()=="r1":
                    nnd=nea.getOpObjects(1)[0]
                    rtype=nea.getOperandRefType(1)
                    if str(rtype)=="READ":
                        addr=int(nnd.toString(),16)
                        v=getDataAt(toAddr(addr)).getValue().toString()
                        if not "0x" in v[:2]:
                            v=toAddr(int(v,16))
                            pstring=getStringAtAddr(v)
                            if pstring is not None:
                                #print("0x%08X:%s" % (v.getOffset(),pstring)) #Here we see all command references from Samsung
                                if "(" in pstring and ")" in pstring:
                                    nea=getInstructionAt(xref)
                                    for pos in range(0,20):
                                        nea=getInstructionBefore(nea)
                                        ppop=nea.getMnemonicString()
                                        if ppop in ("bl","blx"):
                                            fea=nea.getInstructionContext().getAddress()
                                            ffea=getInstructionAt(fea).getOpObjects(0)[0].toString()
                                            sop=toAddr(int(ffea,16))
                                            funcname=pstring[:pstring.index("(")]
                                            print("[Samsung Func Ref] 0x%08X:%s" % (sop.getOffset(),funcname))
                                            setfuncname(sop, funcname)
                                            break
