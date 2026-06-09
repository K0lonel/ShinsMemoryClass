; ##########################################################
; ##                                                      ##
; ##    AutoHotkey memory class by Spawnova - 4/21/2026   ##
; ##                        v2 Port                       ##
; ##                                                      ##
; ##########################################################
;
; To be used in conjunction with ShinsMemoryClass32.dll and ShinsMemoryClass64.dll
;
; dll implementation for increased speed, including multi threaded aob scans
;
; For an overview and basic usage see -> www.youtube.com/watch?v=7OUDVem7AcA
;
; Version 2.0.0 - 4/21/2026
;

class ShinsMemoryClass {

  __New(programIdentifier, access := "all", dllFolder := "") {
    ;a=all, r=read, w=write, o=operation, s=suspend/resume, t=thread, q=query, l=limited query
    static _access := Map("all",0x1F0FFF,"a",0x1F0FFF,"r",0x10,"w",0x20,"o",0x8,"s",0x800,"t",0x2,"q",0x400,"l",0x1000) ;combine for access enums:   "rwq" = Read+write+Query,   "tsl" = thread+suspend/resume+limited query  etc

    this.version := "2.0.0"

    if (!InStr(programIdentifier, "ahk_pid")) {
      if !(hwnd := WinExist(programIdentifier)) {
        throw Error("Could not find a window with the identifer: " programIdentifier)
      }
      pid := WinGetPID(programIdentifier)
    } else {
      pid := SubStr(programIdentifier, 9)
    }

    if (pid = 0) {
      throw Error("Could not find pid for the identifier: " programIdentifier)
    }

    this.pid := pid

    if (access = "all" || access = 0) {
      this.access := _access["all"]
    } else {
      this.access := 0
      for char in StrSplit(access)
        if _access.Has(char)
          this.access |= _access[char]
    }

    this.hProcess := this.OpenProcess(pid, this.access)
    if !this.hProcess {
      throw OSError("Problem getting a handle to the process. Try running the script as Administrator.")
    }

    this.bits := (A_PtrSize == 8)
    this.processBits := (this.bits ? this.GetProcessBits() : 0)
    this.bitStr := (this.bits ? "64" : "32")

    this.ppSize := (this.processBits ? 8 : 4)
    this.ppType := (this.processBits ? "Int64" : "UInt")

    this.lens := Map(
    "char",1,"uchar",1,"short",2,"ushort",2,
    "int",4,"uint",4,"float",4,"double",8,
    "int64",8,"uint64",8,"ptr",A_PtrSize
    )

    this.bPtr := Buffer(0x1000)
    this.uniStr := 1

    this.LoadLib((dllFolder = "" ? "" : RegExMatch(dllFolder, "\\$|\/$") ? dllFolder : dllFolder "\") "ShinsMemoryClass" this.bitStr ".dll")

    this.InitFuncs()
    this.baseAddress := this.ba := this.GetBaseAddress()
  }

  ; ================= POINTER =================

  ; Resolve(address, offsets*) {
  ;   c := offsets.Length
  ;   if (c = 0)
  ;     return address
  ;   else if (c = 1)
  ;     return this.ReadPtr(address + offsets[1])
  ;   else
  ;     return this.GetPtr2(address, offsets)
  ; }

  Resolve(address, offsets*) {
    for k, v in offsets {
      address := this.processBits ? this.ReadInt64_no(address) : this.ReadUInt_no(address)
      address += v
    }
    return address
  }

  ;basically just reads the ptr type of the process, so 64bit would be int64, 32bit is uint, not an ahk pointer, 64 bit ahk reading a 32 bit pointer would return 32 bit
  ReadPtr(address, offsets*) {
    addr := this.Resolve(address, offsets*)
    return this.processBits
      ? this.ReadInt64_no(addr)
      : this.ReadUInt_no(addr)
  }

  WritePtr(address, value, offsets*) {
    addr := this.Resolve(address, offsets*)
    return this.processBits
      ? this.WriteInt64_no(addr, value)
      : this.WriteInt_no(addr, value)
  }

  ;writing values doesn't really need to specify unsigned, it's the same regardless, i have seperate functions mostly for consistency/readability
  ;ahk doesn't support unsigned int64 according to docs, function here just for consistency

  ; ================= READ =================

    ReadChar(address, offsets*) => DllCall(this._ReadInt8  , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Char")
   ReadUChar(address, offsets*) => DllCall(this._ReadInt8  , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "UChar")
   ReadShort(address, offsets*) => DllCall(this._ReadInt16 , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Short")
  ReadUShort(address, offsets*) => DllCall(this._ReadInt16 , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "UShort")
     ReadInt(address, offsets*) => DllCall(this._ReadInt32 , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Int")
    ReadUInt(address, offsets*) => DllCall(this._ReadInt32 , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "UInt")
   ReadFloat(address, offsets*) => DllCall(this._ReadFloat , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Float")
  ReadDouble(address, offsets*) => DllCall(this._ReadDouble, "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Double")
   ReadInt64(address, offsets*) => DllCall(this._ReadInt64 , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Int64")
  ReadUInt64(address, offsets*) => DllCall(this._ReadInt64 , "Ptr", this.hProcess, "Ptr", this.Resolve(address, offsets*), "Int64")

  ; ================= WRITE =================

    WriteChar(address, v, offsets*) => DllCall(this._WriteInt8  , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Char"  , v, "Int")
   WriteUChar(address, v, offsets*) => DllCall(this._WriteInt8  , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "UChar" , v, "Int")
   WriteShort(address, v, offsets*) => DllCall(this._WriteInt16 , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Short" , v, "Int")
  WriteUShort(address, v, offsets*) => DllCall(this._WriteInt16 , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "UShort", v, "Int")
     WriteInt(address, v, offsets*) => DllCall(this._WriteInt32 , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Int"   , v, "Int")
    WriteUInt(address, v, offsets*) => DllCall(this._WriteInt32 , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "UInt"  , v, "Int")
   WriteFloat(address, v, offsets*) => DllCall(this._WriteFloat , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Float" , v, "Int")
  WriteDouble(address, v, offsets*) => DllCall(this._WriteDouble, "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Double", v, "Int")
   WriteInt64(address, v, offsets*) => DllCall(this._WriteInt64 , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Int64" , v, "Int")
  WriteUInt64(address, v, offsets*) => DllCall(this._WriteInt64 , "Ptr", this.hProcess, "Ptr", this.Resolve(address,offsets*), "Int64" , v, "Int")

  ; ================= RAW =================

  ReadRaw(address, &buf, size, offsets*) {
    buf := Buffer(size)
    return DllCall(this._ReadRaw,"Ptr",this.hProcess,"Ptr",this.Resolve(address,offsets*),"Ptr",buf.Ptr,"Int",size,"Int")
  }

  WriteRaw(address, buf, size, offsets*) {
    return DllCall(this._WriteRaw,"Ptr",this.hProcess,"Ptr",this.Resolve(address,offsets*),"Ptr",buf.Ptr,"Int",size,"Int")
  }
  ; ================= STRING =================

  ;write a string of hex bytes
	;WriteByteString(address,"50 51 E9 FF023194 C3")
  WriteByteString(address, bytes, offsets*) {
      addr := this.Resolve(address, offsets*)
      bytes := this.FormatAoBBytes(bytes)
      s := StrSplit(bytes, " ")
      buf := Buffer(s.Length)
      for k, v in s {
          if (RegExMatch(v, "[a-fA-F0-9]{2}", &mm)) {
              val := "0x" mm[0]
              NumPut("UChar", val, buf, A_Index - 1)
          }
      }
      return DllCall(this._WriteRaw, "Ptr", this.hProcess, "Ptr", addr, "Ptr", buf.Ptr, "Int", s.Length, "Int")
  }

  ;general purpose function for reading, these are slower than calling dedicated reads, but only by a tiny fraction
  Read(address, type := "UInt", offsets*) {
    addr := this.Resolve(address, offsets*)
    DllCall(this._Read, "Ptr", this.hProcess, "Ptr", addr, "Ptr", this.bPtr, "UInt", size := this.lens[StrLower(type)])

    return NumGet(this.bPtr, 0, type)
  }

  ;general purpose function for writing, these are slower than calling dedicated writes, but only by a tiny fraction
  Write(address, value, type := "UInt", offsets*) {
    addr := this.Resolve(address, offsets*)
    NumPut(type, value, this.bPtr, 0)

    return DllCall(this._WriteRaw, "Ptr", this.hProcess, "Ptr", addr, "Ptr", this.bPtr, "UInt", this.lens[StrLower(type)], "Int")
  }

  ;get pointer based on address + offsets[]
  GetPointer(address, offsets*) {
    return this.Resolve(address, offsets*)
  }

  ; GetPointer(address, offsets*) {
  ;   bptr := Buffer(1024, 0)
  ;   i := 0

  ;   if this.processBits {
  ;     for v in offsets {
  ;       NumPut("Int64", v, bptr, i)
  ;       i += 8
  ;     }
  ;     return DllCall(this._GetPtr64, "Ptr", this.hProcess, "Int64", address, "Ptr", bptr.Ptr, "UInt", offsets.Length, "Int64")
  ;   } else {
  ;     for v in offsets {
  ;       NumPut("UInt", v, bptr, i)
  ;       i += 4
  ;     }
  ;     return DllCall(this._GetPtr32, "Ptr", this.hProcess, "UInt", address, "Ptr", bptr.Ptr, "UInt", offsets.Length, "UInt")
  ;   }
  ; }

  
  ReadString(address,len:=0,unicode:=0,offsets*) {
    addr := this.Resolve(address,offsets*)
    if (len <= 0)
      len := this.StrLen(addr,unicode)
    if (len <= 0)
      return ""

    size := unicode ? len*2 : len
    buf := Buffer(size)

    if DllCall(this._ReadRaw,"Ptr",this.hProcess,"Ptr",addr,"Ptr",buf.Ptr,"UInt",size,"Int")
      return StrGet(buf, unicode ? "UTF-16" : "UTF-8")

    return ""
  }
  
  WriteString(address,str,unicode:=0,offsets*) {
    return DllCall(this._WriteString,"Ptr",this.hProcess,"Ptr",this.Resolve(address,offsets*),"Str",str,"Int",0,"Int",unicode,"Int",this.uniStr,"Int")
  }

  ;null terminate
  WriteStringNT(address,str,unicode:=0,offsets*) {
    return DllCall(this._WriteString,"Ptr",this.hProcess,"Ptr",this.Resolve(address,offsets*),"Str",str,"Int",1,"Int",unicode,"Int",this.uniStr,"Int")
  }
  

  GetModuleBaseAddress(moduleStr) {
    return DllCall(this._GetModuleBaseAddress, "Ptr", this.hProcess, "AStr", moduleStr, "Ptr")
  }

  Nop(address, bytes) {
    buf := Buffer(bytes, 0x90)
    this.WriteRaw(address, buf, bytes)
  }

  ; ================= AOB =================

  ;scans the entire process memory for an array of bytes, multithreading should only be disabled if it doesn't work for some reason
	;wildcards can be anything that isn't hex ?? ? * ** - . etc. all valid
	;HEX is REQUIRED, decimal values not supported, 0x prefix NOT REQUIRED
	;example string:    FF 00 E9 12345678 00 9F ?? ?? ?? ?? EFF871E9B11A9D C3
  AoB(byteStr,multiThread:=1) {
    bStr := this.FormatAoBBytes(byteStr)
    parts := StrSplit(bStr," ")

    bytes := Buffer(parts.Length)
    mask  := Buffer(parts.Length)

    for i,v in parts {
      if (RegExMatch(v, "[a-fA-F0-9]{2}", &mm)) {
        val := "0x" mm[0]
        NumPut("UChar",val,bytes, i-1)
        NumPut("UChar",0,mask,i-1)
      } else {
        NumPut("UChar",1,mask,i-1)
      }
    }

    return DllCall(multiThread ? this._AobScanMT : this._AoBScan, "Ptr",this.hProcess,"Ptr",bytes.Ptr,"Ptr",mask.Ptr,"UInt",parts.Length,"Ptr")
  }

  AoBModule(module, byteStr) {
    bStr := this.FormatAoBBytes(byteStr)
    parts := StrSplit(bStr," ")

    bytes := Buffer(parts.Length)
    mask  := Buffer(parts.Length)

    for i,v in parts {
      if (RegExMatch(v, "[a-fA-F0-9]{2}", &mm)) {
        val := "0x" mm[0]
        NumPut("UChar",val,bytes, i-1)
        NumPut("UChar",0,mask,i-1)
      } else {
        NumPut("UChar",1,mask,i-1)
      }
    }
    return DllCall(this._AoB_Module, "Ptr", this.hProcess, "Ptr", module, "Ptr", bytes.Ptr, "Ptr", mask.Ptr, "UInt", parts.Length, "Ptr")
  }

  AoBAll(byteStr, &ptrs) {
    ptrs := Buffer(4096, 0)
    bStr := this.FormatAoBBytes(byteStr)
    parts := StrSplit(bStr," ")

    bytes := Buffer(parts.Length)
    mask  := Buffer(parts.Length)

    for i,v in parts {
      if (RegExMatch(v, "[a-fA-F0-9]{2}", &mm)) {
        val := "0x" mm[0]
        NumPut("UChar",val,bytes, i-1)
        NumPut("UChar",0,mask,i-1)
      } else {
        NumPut("UChar",1,mask,i-1)
      }
    }
    return DllCall(this._AoBall, "Ptr", this.hProcess, "Ptr", bytes.Ptr, "Ptr", mask.Ptr, "UInt", parts.Length, "Ptr", ptrs.Ptr, "Ptr")
  }

  ; ================= MEMORY =================

  ;returns an address where there is uncommited memory with a specified byte size
  FindFreeMemory(bytes := 0x1000) {
    return DllCall(this._FindFreeMemory, "Ptr", this.hProcess, "UInt", bytes, "Ptr")
  }

  ;returns an address where there is uncommited memory with a specified byte size but closest to a given address
	;if the closest address is further than maxdist returns -1
  FindFreeMemoryClosest(address, bytes := 0x1000, maxDist := 0x7FFFFFF0) {
    return DllCall(this._FindClosestFreeMemory, "Ptr", this.hProcess, "Ptr", address, "UInt", bytes, "Ptr", maxDist, "Ptr")
  }

  ;returns an address where there is uncommited memory with a specified byte size but nearby a given address
	;if no address is within range returns -1
  FindFreeMemoryNearby(address, bytes := 0x1000, maxDist := 0x7FFFFFF0) {
    return DllCall(this._FindFreeMemoryNearby, "Ptr", this.hProcess, "Ptr", address, "UInt", bytes, "Ptr", maxDist, "Ptr")
  }

  ;if address is 0, it will find the first available region
	;access: r=read, w=write, e=execute    (mix and match, default 0x40 execute-read-write)
	;combine with FindClosestFreeMemory() to alloc near specific addresses
	;returns the base address of allocation if successfull, < 0 otherwise
  Alloc(bytes:=0x1000,address:=0,access:="rwe",topDown:=0) {
    return DllCall(this._AllocMemory,"Ptr",this.hProcess,"Ptr",address,"UInt",bytes,"AStr",access,"UInt",topDown,"Ptr")
  }

  ;frees memory that was allocated, need to specify the allocation base address
  Free(address) {
    return DllCall("Kernel32.dll\VirtualFreeEx","Ptr",this.hProcess,"Ptr",address,"Ptr",0,"UInt",0x8000,"UInt")
  }

  ; ================= PROCESS =================

  OpenProcess(pid,access) {
    return DllCall("Kernel32.dll\OpenProcess","UInt",access,"Int",0,"UInt",pid,"Ptr")
  }

  ;suspends the process, pausing it essentially
  Suspend() => DllCall("ntdll.dll\NtSuspendProcess","Ptr",this.hProcess)
  ;resume the process
  Resume()  => DllCall("ntdll.dll\NtResumeProcess","Ptr",this.hProcess)

  ; =============== PROTECTION ===============

  ;simple wrapper function for making a single protected call
  WriteProt(address, value, type := "Uint", offsets*) {
    addr := this.Resolve(address,offsets*)
    if !(old := this.Unprotect(addr))
      return 0
    v := this.Write(addr, value, type)
    this.Protect(addr, old)
    return v
  }

  ;unprotect a region of memory, giving it read+write+execute
  Unprotect(address, sz := 4) {
    lpflOldProtect := 0
    if (!DllCall("Kernel32.dll\VirtualProtectEx", "Ptr", this.hProcess, "Ptr", address, "UInt", sz, "UInt", 0x40, "Ptr*", &lpflOldProtect))
      return 0
    return lpflOldProtect
  }

  ;sets a new protection, use the return value of Unprotect to restore the old protection
  Protect(address, prot, sz := 4) {
    oldProt := 0
    if (!DllCall("Kernel32.dll\VirtualProtectEx", "Ptr", this.hProcess, "Ptr", address, "UInt", sz, "UInt", prot, "UInt*", &oldProt))
      return 0
    return 1
  }

  ; ================= THREAD =================

  CreateThread(address,suspended:=0) {
    return DllCall("Kernel32\CreateRemoteThread","Ptr",this.hProcess,"Ptr",0,"Ptr",0,"Ptr",address,"Ptr",0,"UInt",(suspended?0x4:0x0),"Ptr*",0,"Ptr")
  }

  ;0xFFFFFFFF = infite wait, 0 = no wait
  WaitThread(hThread,timeout:=0xFFFFFFFF) {
    return DllCall("Kernel32\WaitForSingleObject","Ptr",hThread,"UInt",timeout,"UInt")
  }

  CloseThread(hThread) {
    DllCall("Kernel32.dll\CloseHandle","Ptr",hThread,"UInt")
  }

  ResumeThread(hThread) {
    return DllCall("Kernel32\ResumeThread","Ptr",hThread,"UInt")
  }

  ;create a thread and execute code at a specified address
  Execute(address) {
    ; this.Suspend()
    if hThread := this.CreateThread(address) {
      this.WaitThread(hThread,5000)
      this.CloseThread(hThread)
    }
    ; this.Resume()
  }

  ConvertCEString() {
    if (RegExMatch(A_Clipboard, "\S\S\S\S\S\S\S\S - ")) {
      str := ""
      loop parse, A_Clipboard, "`n", "`r" {
        s := RegExReplace(A_LoopField, "\{[^\}]+\}", "")
        s := StrSplit(s, "-", "", 3)
        if (s.Length < 3)
          continue

        s2 := RegExReplace(s[2], "^ |\s+$", "")
        s3 := RegExReplace(s[3], "^ |\s+$", "")
        line := s2
        if (RegExMatch(s2, "(\S\S)(\S\S)(\S\S)(\S\S)", &mm)) {
          be := mm[4] mm[3] mm[2] mm[1]
          le := mm[1] mm[2] mm[3] mm[4]
          if (!InStr(s3, be)) {
            if (RegExMatch(s3, "dll\+|\[........]|exe\+|\[........]")) {
              if (RegExMatch(s3, "jmp |jne |jg |je |jl |jng |jge |jle |je |jb |ja "))
                line := StrReplace(line, le, "+")
              else if (InStr(s2, "call "))
                line := StrReplace(line, le, "@")
              else
                line := StrReplace(line, le, "!")
            }
          }
        }
        nn := 0
        while (RegExMatch(line, "(\S\S)\S", &mm)) {
          line := RegExReplace(line, mm[1] "(\S)", mm[1] " $1", &nn, 1)
        }
        line := StrReplace(line, "!", "REPLE")
        line := StrReplace(line, "+", "JUMP")
        line := StrReplace(line, "@", "CALL")
        str .= (str = "" ? "str := " '"' : "`nstr .= " '" ') line '" ' " `;" s3
      }
      A_Clipboard := str
      return 1
    }
    return 0
  }

  ; ================= INTERNAL =================
  
  __delete() => DllCall("Kernel32.dll\CloseHandle", "Ptr", this.hProcess)
  
  LoadLib(lib*) {
    for k, v in lib {
      if (!DllCall("Kernel32.dll\GetModuleHandle", "Str", v, "Ptr")) {
        hm := DllCall("Kernel32.dll\LoadLibrary", "Str", v)
        if (hm = 0) {
          MsgBox("Unable to load module: " v)
        }
      }
    }
  }
  
  GetProcessBits() {
    if (this.access & (0x400 | 0x1000)) {
      wow64 := 0
      if DllCall("Kernel32.dll\IsWow64Process", "Ptr", this.hProcess, "Int*", &wow64)
        return !wow64
    } else {
      tHandle := this.OpenProcess(this.pid, 0x1000)
      wow64 := 0
      v := DllCall("Kernel32.dll\IsWow64Process", "Ptr", this.hProcess, "Int*", &wow64)
      DllCall("Kernel32.dll\CloseHandle", "Ptr", tHandle)
      if (v)
        return !wow64
    }
    return 1
  }

  GetPtr2(address, offsets) {
    bPtr := Buffer(1024, 0)
    i := 0
    if (this.processBits) {
      for k, v in offsets {
        NumPut("Int64", v, bPtr, i)
        i += 8
      }
      return DllCall(this._GetPtr64, "Ptr", this.hProcess, "Int64", address, "Ptr", bPtr.Ptr, "UInt", offsets.Length, "Int64")
    } else {
      for k, v in offsets {
        NumPut("UInt", v, bPtr, i)
        i += 4
      }
      return DllCall(this._GetPtr32, "Ptr", this.hProcess, "UInt", address, "Ptr", bPtr.Ptr, "UInt", offsets.Length, "UInt")
    }
  }

  
  InitFuncs() {
    if (!mdl := DllCall("Kernel32.dll\GetModuleHandle", "Str", "ShinsMemoryClass" this.bitStr, "Ptr")) {
      throw Error("DLL not loaded! Put ShinsMemoryClass" this.bitStr ".dll in script folder or provide correct dllFolder path.")
    }
    GetProcAddress := (n) => DllCall("Kernel32.dll\GetProcAddress", "Ptr", mdl, "AStr", n, "Ptr")

    this._ReadRaw               := GetProcAddress("ReadRawBytes")
    this._ReadDouble            := GetProcAddress("ReadDouble")
    this._ReadFloat             := GetProcAddress("ReadFloat")
    this._ReadInt64             := GetProcAddress("ReadInt64")
    this._ReadInt32             := GetProcAddress("ReadInt32")
    this._ReadInt16             := GetProcAddress("ReadInt16")
    this._ReadInt8              := GetProcAddress("ReadInt8")

    this._WriteRaw              := GetProcAddress("WriteRawBytes")
    this._WriteDouble           := GetProcAddress("WriteDouble")
    this._WriteFloat            := GetProcAddress("WriteFloat")
    this._WriteInt64            := GetProcAddress("WriteInt64")
    this._WriteInt32            := GetProcAddress("WriteInt32")
    this._WriteInt16            := GetProcAddress("WriteInt16")
    this._WriteInt8             := GetProcAddress("WriteInt8")

    this._GetPtr64              := GetProcAddress("GetPtr64")
    this._GetPtr32              := GetProcAddress("GetPtr32")
    this._GetPtr                := GetProcAddress("GetPointer")

    this._WriteString           := GetProcAddress("WriteString")
    this._StrLen                := GetProcAddress("StrLen")

    this._GetModuleBaseAddress  := GetProcAddress("GetModuleBaseAddress")
    this._GetBaseAddress        := GetProcAddress("GetBaseAddress")
    this._AllocMemory           := GetProcAddress("AllocMemory")
    this._AoB_Module            := GetProcAddress("AoB_Module")
    this._AoBScanMT             := GetProcAddress("AoBScanMT")
    this._AoBScan               := GetProcAddress("AoBScan")
    this._aoball                := GetProcAddress("AoBScanAll")

    this._FindClosestFreeMemory := GetProcAddress("FindClosestFreeMemory")
    this._FindFreeMemoryNearby  := GetProcAddress("FindFreeMemoryNearby")
    this._FindFreeMemory        := GetProcAddress("FindFreeMemory")
    this._RelBytes64            := GetProcAddress("RelOffset64")
    this._RelBytes              := GetProcAddress("RelOffset")
    this._Read                  := GetProcAddress("rRead")

    this._ExplodeHex64          := GetProcAddress("ExplodeHex64")
    this._ExplodeHex            := GetProcAddress("ExplodeHex")
    this._ToHex64               := GetProcAddress("ToHex64")
    this._ToHex                 := GetProcAddress("ToHex")
  }
  
  ToHex(val, prefix := 1, bits := 0) {
    if (bits) {
      len := DllCall(this._ToHex64, "Ptr", this.bPtr, "Int64", val, "UInt", prefix)
      return StrGet(this.bPtr, len, "utf-8")
    }
    len := DllCall(this._ToHex, "Ptr", this.bPtr, "UInt", val, "UInt", prefix)
    return StrGet(this.bPtr, len, "utf-8")
  }
  
  ; FormatAoBBytes(byteStr) {
	; 	byteStr := RegExReplace(byteStr,"\s\s+"," ")
	; 	byteStr := RegExReplace(byteStr,"^\s+|\s+$","")
	; 	while RegExMatch(byteStr," (\S\S)(\S)")
	; 		byteStr := RegExReplace(byteStr," (\S\S)(\S)"," $1 $2")
	; 	while RegExMatch(byteStr,"(\S)(\S\S) ")
	; 		byteStr := RegExReplace(byteStr,"(\S)(\S\S) ","$1 $2 ")
	; 	return byteStr
	; }
  
  FormatAoBBytes(byteStr) {
    ; 1. Smash all big gaps into single spaces and trim dirt off the ends
    byteStr := RegExReplace(Trim(byteStr), "\s+", " ")

    ; 2. The Lookahead Magic!
    ; It automatically runs through the whole string and chops every solid
    ; block of characters into 2-rock pieces. No 'while' loop needed!
    return RegExReplace(byteStr, "(\S\S)(?=\S)", "$1 ")
  }
  
  StrLen(address, unicode := 0) => DllCall(this._StrLen, "Ptr", this.hProcess, "Ptr", address, "Int", unicode, "UInt")
  WriteInt64_no(address, v)     => DllCall(this._WriteInt64, "Ptr", this.hProcess, "Ptr", address, "Int64", v, "Int")
  WriteInt_no(address, v)       => DllCall(this._WriteInt32, "Ptr", this.hProcess, "Ptr", address, "Int", v, "Int")
  ReadInt64_no(address)         => DllCall(this._ReadInt64, "Ptr", this.hProcess, "Ptr", address, "Int64")
  ReadUInt_no(address)          => DllCall(this._ReadInt32, "Ptr", this.hProcess, "Ptr", address, "UInt")
  GetBaseAddress()              => DllCall(this._GetBaseAddress, "Ptr", this.hProcess, "Ptr")

  ExplodeHex(val, bits := 0, swap := 0) {
    if (bits) {
      DllCall(this._ExplodeHex64, "Ptr", this.bPtr, "Int64", val, "UInt", swap)
      return StrGet(this.bPtr, 23, "UTF-8")
    } else {
      DllCall(this._ExplodeHex, "Ptr", this.bPtr, "UInt", val, "UInt", swap)
      return StrGet(this.bPtr, 11, "UTF-8")
    }
  }

  RelBytes(from, to, bits := 0) {
    if (bits)
      return DllCall(this._RelBytes64, "Int64", from, "Int64", to)
    return DllCall(this._RelBytes, "UInt", from, "UInt", to)
  }
}

; ##########################################################
; HookHelper
; ##########################################################

;simple helper class for writing asm, commits a region and half is reserved for code execution, the other half for storage
class HookHelper {
    __New(mem, storeAddress, size := 0x1000, start := 0, init := 0xCCCCCCCC, maxDist := 0x7FFFFFF0) {
        this.bits := mem.bits
        this.size := Max(Ceil(size / 0x1000), 1) * 0x1000
        this.mem := mem
        this.address := 0
        this.pcache := 0
        this.current := 0
        this.currentCache := 0
        this.temp := 0

        if (!pmem := this.RegionPtr(storeAddress, size, start, init)) {
            MsgBox("Problem allocating a region to store at " mem.ToHex(storeAddress, 1, mem.processBits))
        }
    }

    ;helper function that checks a static address for a ptr to a commited region and return it
	  ;or if no ptr is found, create a new region and store it's address into the static address
	  ;if the value at address equals INIT, then create a new region with SIZE bytes, located near START, within MAXDIST
	  ;should only be called if the initial call fails when instantiating the class
    RegionPtr(address, size := 0x1000, start := 0, init := 0xCCCCCCCC, maxDist := 0x7FFFFFF0) {
        if (this.mem.ReadUInt(address) = init) {
            if (start <= 0) {
                pmem := this.mem.Alloc(size)
            } else {
                start := this.mem.FindFreeMemoryNearby(start, size, maxDist)
                if (start = -1) {
                    MsgBox("RegionPtr Error:`nFailed to find free memory close to " this.mem.ToHex(start, 1, this.mem.processBits
                    ))
                    return 0
                }
                pmem := this.mem.Alloc(size, start)
            }

            if (pmem < 0) {
                MsgBox("RegionPtr Error:`nFailed to alloc - " DllCall("Kernel32.dll\GetLastError") " (" this.mem.ToHex(
                    DllCall("ntdll.dll\RtlGetLastNtStatus"), 1) ")")
                return 0
            }

            olp := this.mem.Unprotect(address, 8)
            this.mem.WritePtr(address, pmem)
            this.mem.Protect(address, olp, 8)

        } else {
            pmem := this.mem.ReadPtr(address)
        }

        this.size := size
        this.address := pmem
        this.pcache := this.address + Round(this.size / 2)
        this.current := this.address
        this.currentCache := this.pcache
        this.temp := this.pcache + 4

        return pmem
    }

    ;replace special instructions with args
    WriteAsm(str, args*) {
        s := StrSplit(str, " ")
        out := ""
        i := 1
        start := this.current
        for k, v in s {
            out .= (A_Index = 1 ? "" : " ")
            if (v = "REPLE") {
                out .= this.mem.ExplodeHex(args[i], 0, 1)
                this.current += 4
                i++
            } else if (v = "REPLE64") {
                out .= this.mem.ExplodeHex(args[i], 1, 1)
                this.current += 8
                i++
            } else if (v = "REP") {
                out .= this.mem.ExplodeHex(args[i])
                this.current += 4
                i++
            } else if (v = "REP64") {
                out .= this.mem.ExplodeHex(args[i], 1)
                this.current += 8
                i++
            } else if (v = "CALL") {
                out .= this.RelSwapStr(this.current + 4, args[i])
                this.current += 4
                i++
            } else if (v = "JUMP") {
                out .= this.RelSwapStr(this.current + 4, args[i])
                this.current += 4
                i++
            } else if (v = "JUMP2") {
                diff := args[i] - this.current
                if (Abs(diff) > 127) {
                    out .= "E9 " this.RelSwapStr(this.current + 5, args[i])
                    this.current += 5
                    i++
                } else {
                    if (diff > 0)
                        out .= "EB " this.mem.ToHex(diff - 1)
                    else
                        out .= "EB " this.mem.ToHex(255 + (diff - 1))
                    this.current += 2
                    i++
                }
            } else if (v = "JNE") {
                diff := args[i] - this.current
                if (Abs(diff) > 127) {
                    out .= "0F 85 " this.RelSwapStr(this.current + 6, args[i])
                    this.current += 6
                    i++
                } else {
                    if (diff > 0)
                        out .= "75 " this.mem.ToHex(diff - 1)
                    else
                        out .= "75 " this.mem.ToHex(255 + (diff - 1))
                    this.current += 2
                    i++
                }
            } else if (RegExMatch(v, "REL_([^_]+)_([^_]+)_(\d)", &mm)) {
                out .= (mm[3] ? this.RelSwapStr64(this.current + 8, mm[2]) : this.RelSwapStr(this.current + 4, mm[2]))
                this.current += (mm[3] ? 8 : 4)
                i += mm[1]
            } else {
                this.current++
                out .= v
            }
        }

        loop 5 {
            if (A_Index > 1 and Mod(this.current, 4) = 0)
                break
            out .= (out = "" ? "" : " ") "90"
            this.current++
        }

        this.mem.WriteByteString(start, out)
        return start
    }

    ToAsmCall(start, func, hex := 1, bigE := 0) {
        if (func > start) {
            diff := func - start - 1
            return (bigE ? diff : this.ToLittleEndian(diff, hex))
        } else {
            diff := 0xFFFFFFFF - (start - func)
            return (bigE ? diff : this.ToLittleEndian(diff, hex))
        }
    }

    ToLittleEndian(n, hex := 1) {
        a := (n & 0xFF000000) >> 24
        b := (n & 0xFF0000) >> 16
        c := (n & 0xFF00) >> 8
        d := (n & 0xFF)
        v := (d << 24) + (c << 16) + (b << 8) + a
        return (hex ? this.mem.ExplodeHex(v, 0, 1) : v)
    }

    ;hook with a 32 bit relative jump
    Hook(fromAddress, toAddress, force := 0, nops := 0) {
        if (!force and this.mem.ReadUChar(fromAddress) = 0xE9) {
            return
        }

        asm := "E9 " this.RelSwapStr(fromAddress + 5, toAddress)
        loop nops
            asm .= " 90"

        prot := this.mem.Unprotect(fromAddress)
        this.mem.WriteByteString(fromAddress, asm)
        this.mem.Protect(fromAddress, prot)
    }

    ;hook with a 64 bit absolute jump
    Hook64(fromAddress, toAddress, force := 0, nops := 0) {
        if (!force and this.mem.ReadUShort(fromAddress) = 0x25FF) {
            return
        }
        asm := "FF 25 00 00 00 00 " this.mem.ExplodeHex(toAddress, 1, 1)
        loop nops
            asm .= " 90"

        prot := this.mem.Unprotect(fromAddress)
        this.mem.WriteByteString(fromAddress, asm)
        this.mem.Protect(fromAddress, prot)
    }

    RelSwapStr(from, to) => this.mem.ExplodeHex(this.mem.RelBytes(from, to))
    RelSwapStr64(from, to) => this.mem.ExplodeHex64(this.mem.RelBytes64(from, to))

    ;helper function, find a free address in our region and move the index forward x bytes
    ReserveCache(size) {
        s := this.currentCache
        this.currentCache += size
        this.currentCache += Mod(this.currentCache, 4) ;always be 4 byte aligned
        this.temp := this.currentCache
        return s
    }

  REL(address,ops:=1,bits:=0) => ("REL_" ops "_" this.mem.tohex(address,1,bits) "_" bits)
	REPLE(var,bits:=0) => this.mem.explodehex(var,bits,1)
	JUMP(address,bits:=0) => ("REL_1_" this.mem.tohex(address,1,bits) "_" bits)
}