;/*

Function MdsIPImage
  case !version.os of
    'vms' : return,'mdsipshr'
    'windows' : return,'mdsipshr'
    'AIX' : return,'libMdsIpShr.lib'
    'IRIX' : return,'libMdsIpShr.so'
    'OSF' : return,'libMdsIpShr.so'
    'sunos' : return,'libMdsIpShr.so'
    'hp-ux' : return,getenv('MDS_SHLIB_PATH')+'/libMdsIpShr.sl'
    else  : message,'MDS is not supported on this platform',/IOERROR 
  endcase
end

function MdsRoutinePrefix
  if !version.os eq 'vms' then return,'' else return,'Idl'
end

Pro MdsMemCpy,outvar,inptr,num
  case !version.os of
    'vms' :  dummy = call_external('decc$shr','decc$memcpy',outvar,inptr,num,value=[0,1,1])
    'OSF' :  dummy = call_external(MdsIpImage(),MdsRoutinePrefix()+'memcpy',outvar,inptr,num,value=[0,0,1])
    else  :  dummy = call_external(MdsIpImage(),MdsRoutinePrefix()+'memcpy',outvar,inptr,num,value=[0,1,1])
  endcase
  return
end

function mds$socket,quiet=quiet,status=status
  sock = 0l
  defsysv,'!MDS_SOCKET',exists=old_sock
  if not old_sock then defsysv,'!MDS_SOCKET',sock else tmp = execute('sock=!MDS_SOCKET')
  if sock eq 0 then begin
    status = 0
    if not keyword_set(quiet) then message,'Use MDS$CONNECT to connect to a host.',/continue
    return,0
  endif
  status = 1
  return,sock
end

pro Mds$SendArg,sock,n,idx,arg 
  s = size(arg) 
  ndims = s(0) 
  dims = lonarr(8) 
  if ndims gt 0 then for i=1,ndims do dims(i-1) = s(i) 
  dtype = s(ndims + 1) 
  dtypes =  [0,2,7,8,10,11,12,14,0] 
  lengths = [0,1,2,4,4,8,8,1,0] 
  dtype = dtypes(dtype) 
  if dtype eq 14 then begin
    length = strlen(arg)
    argByVal = 1b
    if !version.os eq 'windows' then argByVal = 0b
  endif else begin
    length = lengths(dtype)
    argByVal = 0b
  endelse
  x = call_external(MdsIPImage(),MdsRoutinePrefix()+'SendArg',sock,idx,dtype,n,length,ndims,dims,arg,value=[1b,1b,1b,1b,1b,1b,0b,argByVal]) 
  return
end 

pro mds$connect,host,status=status,quiet=quiet
  mds$disconnect,/quiet
  sock = call_external(MdsIPImage(),MdsRoutinePrefix()+'ConnectToMds',host,value=[byte(!version.os ne 'windows')])
  if (sock gt 0) then begin
    x=execute('!MDS_SOCKET = sock')
  endif else begin
    if not keyword_set(quiet) then message,'Error connecting to '+host,/IOERROR
    status = -1
  endelse
  return
end  

pro mds$disconnect,status=status,quiet=quiet
  status = 1
  sock = mds$socket(status=status,quiet=quiet)
  if status then begin
    status = call_external(MdsIPImage(),MdsRoutinePrefix()+'DisconnectFromMds',sock,value=[1b])
    if (status eq 0) then status = 1 else status = 0
    tmp = execute('!MDS_SOCKET = 0l')
  endif
  return
end  

function mds$value,expression,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12, $
             arg13,arg14,arg15,arg16,arg17,arg18,arg19,arg20,arg21,arg22,arg23,arg24,arg25, $
             arg26,arg27,arg28,arg29,arg30,arg31,arg32,status=status,quiet=quiet
  sock = mds$socket(status=status,quiet=quiet)
  if not status then return,0
  n = n_params()
  Mds$SendArg,sock,n,0,expression
  for i=1,n-1 do x = execute('Mds$SendArg,sock,n,i,arg'+strtrim(i,2))
  dtype = 0b
  ndims = 0b
  dims = lonarr(8)
  numbytes = 0l
  answer = 0
  length = 0
  ansptr = 0l
  if !version.os eq 'OSF' then ansptr = lonarr(2)
  status = call_external(MdsIPImage(),MdsRoutinePrefix()+'GetAnsInfo',sock,dtype,length,ndims,dims,numbytes,ansptr,value=[1,0,0,0,0,0,0])
  if numbytes gt 0 then begin
    if dtype eq 14 then begin
      if ndims ne 0 then begin
        s = 'answer = bytarr(length,'
        for i=0,ndims-1 do s = s + 'dims(' + strtrim(i,2) + '),'
        strput,s,')',strlen(s)-1
        x = execute(s)
      endif else begin
        answer = bytarr(length)
      endelse
      MdsMemCpy,answer,ansptr,numbytes
      answer = string(answer)
    endif else begin
      if ndims ne 0 then begin
        s = 'answer = bytarr('
        for i=0,ndims-1 do s = s + 'dims(' + strtrim(i,2) + '),'
        strput,s,')',strlen(s)-1
        x = execute(s)
      endif else answer = 0b
      case dtype of
      2: answer = answer
      3: answer = fix(answer)
      4: answer = long(answer)
      7: answer = fix(answer)
      8: answer = long(answer)
      10: answer = float(answer)
      11: answer = double(answer)
      12: answer = complex(answer)
      else: message,'Data type '+string(dtype)+'  is not supported',/continue
      endcase
      MdsMemCpy,answer,ansptr,numbytes
    endelse
    if not (status and 1) then begin
      if keyword_set(quiet) then message,answer,/noprint,/continue else message,answer,/continue
      answer = 0
    endif
  endif else begin
    if not keyword_set(quiet) then message,'Error evaluating expression',/continue
    answer = 0
  endelse
  return,answer
end

pro mds$put,node,expression,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12, $
             arg13,arg14,arg15,arg16,arg17,arg18,arg19,arg20,arg21,arg22,arg23,arg24,arg25, $
             arg26,arg27,arg28,arg29,arg30,arg31,arg32,status=status,quiet=quiet
  sock = mds$socket(status=status,quiet=quiet)
  if not status then return
  n = n_params()
  lexpression = 'mdslib->mds$put('
  for i=0,n-1 do lexpression = lexpression + 'descr($'+strtrim(i+1,2)+'),'
  strput,lexpression,')',strlen(lexpression)-1
  mds$sendarg,sock,n+1,0,lexpression
  mds$sendarg,sock,n+1,1,node
  mds$sendarg,sock,n+1,2,expression
  for i=1,n-2 do x = execute('mds$sendarg,sock,n+1,i+2,arg'+strtrim(i,2))
  dtype = 0b
  ndims = 0b
  dims = lonarr(8)
  numbytes = 0l
  answer = 0
  length = 0
  ansptr = 0l
  status = call_external(MdsIPImage(),MdsRoutinePrefix()+'GetAnsInfo',sock,dtype,length,ndims,dims,numbytes,ansptr,value=[1,0,0,0,0,0,0])
  if numbytes gt 0 then begin
    if dtype eq 14 then begin
      if ndims ne 0 then begin
        s = 'answer = bytarr(length,'
        for i=0,ndims-1 do s = s + 'dims(' + strtrim(i,2) + '),'
        strput,s,')',strlen(s)-1
        x = execute(s)
      endif else begin
        answer = bytarr(length)
      endelse
      MdsMemCpy,answer,ansptr,numbytes
      answer = string(answer)
    endif else begin
      if ndims ne 0 then begin
        s = 'answer = bytarr('
        for i=0,ndims-1 do s = s + 'dims(' + strtrim(i,2) + '),'
        strput,s,')',strlen(s)-1
        x = execute(s)
      endif else answer = 0b
      case dtype of
      2: answer = answer
      3: answer = fix(answer)
      4: answer = long(answer)
      7: answer = fix(answer)
      8: answer = long(answer)
      10: answer = float(answer)
      11: answer = double(answer)
      12: answer = complex(answer)
      else: message,'Data type '+string(dtype)+'  is not supported',/ioerror
      endcase
      MdsMemCpy,answer,ansptr,numbytes
    endelse
    status = answer
  endif else begin
    if not keyword_set(quiet) then message,'Error evaluating expression',/IOERROR
    answer = -1
  endelse
  return
end

function mds$getmsg,status,quiet=quiet
  return,MDS$VALUE('getmsg($)', status,quiet=quiet)
end

PRO MDS$SET_DEF,NODE,QUIET=QUIET,STATUS=STATUS
;
;+
; NAME:
;	MDS$SET_DEF
; PURPOSE:
;	Set default to a node in an MDSplus tree
; CATEGORY:
;	MDSPLUS
; CALLING SEQUENCE:
;	MDS$SET_DEF,NODE
; INPUT PARAMETERS:
;	node = Node specification.
; Keywords:
;       QUIET = prevents IDL error if TCL command fails
;       STATUS = return status, low bit set = success
; OUTPUTS:
;       istat = return status, low bit set = success
; COMMON BLOCKS:
;	None.
; SIDE EFFECTS:
;	None.
; RESTRICTIONS:
;	None.
; PROCEDURE:
;	Straightforward.  Makes a call to MDSplus shared image library
;       procedure MDS$SET_DEFAULT and checks for errors.
; MODIFICATION HISTORY:
;	 VERSION 1.0, CREATED BY T.W. Fredian, April 22,1991
;-
;
ON_ERROR,2		;RETURN TO CALLER IF ERROR
sock = mds$socket(quiet=quiet,status=status)
if not status then return
status = call_external(MdsIPImage(),MdsRoutinePrefix()+'MdsSetDefault',sock,string(node),value=[1b,byte(!version.os ne 'windows')])
if not status then begin
  if keyword_set(quiet) then message,mds$getmsg(status,quiet=quiet),/continue,/noprint $
                        else message,mds$getmsg(status,quiet=quiet),/continue
endif
return
end

PRO MDS$OPEN,EXPERIMENT,SHOT,QUIET=QUIET,STATUS=STATUS
;
;+
; NAME:
;	MDS$OPEN
; PURPOSE:
;	Open an MDSplus experiment model or pulse file
; CATEGORY:
;	MDSPLUS/IP
; CALLING SEQUENCE:
;	MDS$OPEN,experiment,shot[,/QUIET][,STATUS=ISTAT]
; INPUT PARAMETERS:
;	experiment = name of the experiment whose model or pulse
;                    file you want to open.
;       shot       = shot number of the file.
; Keywords:
;       QUIET = prevents IDL error if TCL command fails
;       STATUS = return status, low bit set = success
; OUTPUTS:
;       istat = return status, low bit set = success
; COMMON BLOCKS:
;	None.
; SIDE EFFECTS:
;	None.
; RESTRICTIONS:
;	None.
; PROCEDURE:
;	Straightforward.  Makes a call to MDSplus shared image library
;       procedure MDS$OPEN and checks for errors.
; MODIFICATION HISTORY:
;	 VERSION 1.0, CREATED BY T.W. Fredian, April 22,1991
;-
;
ON_ERROR,2		;RETURN TO CALLER IF ERROR
;
; Determine whether experiment and shot were provided.
;
sock = mds$socket(quiet=quiet,status=status)
if not status then return
status = call_external(MdsIPImage(),MdsRoutinePrefix()+'MdsOpen',sock,string(experiment),long(shot),value=[1b,byte(!version.os ne 'windows'),1b])
return
if not status then begin
  if keyword_set(quiet) then message,mds$getmsg(status,quiet=quiet),/continue,/noprint $
                        else message,mds$getmsg(status,quiet=quiet),/continue
endif
RETURN
END

PRO MDS$CLOSE,EXPERIMENT,SHOT,QUIET=QUIET,STATUS=STATUS
;
;+
; NAME:
;	MDS$CLOSE (TCPIP version)
; PURPOSE:
;	Close an open MDSplus experiment model or pulse file
; CATEGORY:
;	MDSPLUS/IP
; CALLING SEQUENCE:
;	MDS$CLOSE[,experiment,shot][,/QUIET,STATUS=ISTAT]
; OPTIONAL INPUT PARAMETERS:
;	experiment = name of the experiment used in an invocation
;                    of MDS$OPEN.
;       shot       = shot number of the file.
;       If both experiment and shot are omitted, all files will be
;       closed.
; Keywords:
;       QUIET = prevents IDL error if TCL command fails
;       STATUS = return status, low bit set = success
; OUTPUTS:
;       istat = return status, low bit set = success
; OUTPUTS:
;	None.
; COMMON BLOCKS:
;	None.
; SIDE EFFECTS:
;	None.
; RESTRICTIONS:
;	None.
; PROCEDURE:
;	Straightforward.  Makes a call to MDSplus shared image library
;       procedure MDS$CLOSE and checks for errors.
; MODIFICATION HISTORY:
;	 VERSION 1.0, CREATED BY T.W. Fredian, April 22,1991
;-
;
ON_ERROR,2		;RETURN TO CALLER IF ERROR
;
; Determine whether experiment and shot were provided.
;
sock = mds$socket(quiet=quiet,status=status)
if not status then return
sock = call_external(MdsIPImage(),MdsRoutinePrefix()+'MdsClose',sock,value=[1b])
if not status then begin
  if keyword_set(quiet) then message,mds$getmsg(status,quiet=quiet),/continue,/noprint $
                        else message,mds$getmsg(status,quiet=quiet),/continue
endif
RETURN
END

pro connect,host,_EXTRA=e
	mds$connect,host,_EXTRA=e
return
end

;*/
