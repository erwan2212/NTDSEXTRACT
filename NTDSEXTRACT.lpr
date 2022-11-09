//dump with powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
//on win10 if esentutl fails with callback error:
//Enable-WindowsOptionalFeature -FeatureName ‘DirectoryServices-ADAM-Client’ -Online

//compilation optimization level >1 will mess up results ???
program project1;

uses windows, sysutils, math, esent, JwaWinCrypt, jwanative,ntds, utils{,jwawintype,jwabcrypt};

function ConvertSidToStringSidA(SID: PSID; var StringSid: pchar): Boolean; stdcall;
    external 'advapi32.dll';// name 'ConvertSidToStringSidA';

var
columns:array of COLUMN_INFO;
syskey:tbytes;


const
  dummy=0;
  //should be retrieved from system or given on the command line
  //syskey :array[0..SYSTEM_KEY_LEN-1] of byte= ( $2e,$24,$1b,$23,$bb,$27,$af,$6c,$ef,$7f,$e7,$d6,$d7,$a9,$66,$64);

function GetColumnId(uAttrId:ULONG):ulong;
var
Id:ULONG = 0;
i:integer;
begin
  for i := 0 to length(columns)-1 do
    begin
    if (uAttrId = columns[i].uAttrId) then
      begin
      Id := columns[i].uColumnId;
      break;
      end;
  end;
  result:=Id;
end;



// *  + Obtain user attributes
// *  + Decrypt hashes
function GetHashes(bHistory,bInactive, bMachines:BOOL):boolean;
const
  empty_lm:array[0..15] of byte=($aa,$d3,$b4,$35,$b5,$14,$04,$ee,$aa,$d3,$b4,$35,$b5,$14,$04,$ee);
  empty_nt:array[0..15] of byte=($31,$d6,$cf,$e0,$d1,$6a,$e9,$31,$b7,$3c,$59,$d7,$e0,$c0,$89,$c0);
var
  samName, description, path:array [0..255] of widechar;
  lmHash, ntHash,lmHistory, ntHistory, sid:array [0..255] of byte;
  dwCount,rid, dwUsers, dwUserCtrl, ntHashes, lmHashes, dwHistory:dword;
  uacId, sidId, lmId, ntId, samId, descId, homeId, lmHistId, ntHistId: ulong;
  err:JET_API;
  stringsid:pchar;
  c:byte;
  dwlen:dword;
begin
  result:=false;
  // get column ids corresponding to user attributes
   uacId   := GetColumnId(ATT_USER_ACCOUNT_CONTROL);
   sidId   := GetColumnId(ATT_OBJECT_SID);
   lmId    := GetColumnId(ATT_DBCS_PWD);
   ntId    := GetColumnId(ATT_UNICODE_PWD);
   samId   := GetColumnId(ATT_SAM_ACCOUNT_NAME);
   descId  := GetColumnId(ATT_DESCRIPTION);
   homeId  := GetColumnId(ATT_HOME_DIRECTORY);

  // history
   lmHistId  := GetColumnId(ATT_LM_PWD_HISTORY);
   ntHistId  := GetColumnId(ATT_NT_PWD_HISTORY);

  // ensure we all column ids before continuing
  if (sidId = 0) or (lmId = 0) or (ntId = 0)
  or (uacId = 0) or (samId = 0) or (descId = 0) or (homeId = 0) then exit;


  //bPrintSize := FALSE;

   //* open the datatable

  err := JetOpenTableA(psesid, pdbid , 'datatable', nil, 0, JET_bitTableReadOnly or JET_bitTableSequential, ptable_id);

  if (err <> JET_errSuccess) then exit;


  // go to first row
  err := JetMove(psesid, ptable_id, JET_MoveFirst, JET_bitNil);

    dwHistory := 0;
    ntHashes := 0;
    lmHashes := 0;
    dwUsers := 0;

    while 1=1 do
    begin
    //* get the user account control value
    dwUserCtrl:=0;
    if GetColumnData(uacId, @dwUserCtrl, sizeof(dwUserCtrl))>0 then ; //writeln(dwUserCtrl);
    //* get sAMAccountName
    if GetColumnData(samId, @samName[0], sizeof(samName))>0 then
    begin

    if GetColumnData(sidId, @sid[0], sizeof(sid))>0 then
      begin
      dwCount := GetSidSubAuthorityCount(@sid[0])^;
      rid := GetSidSubAuthority(@sid[0], dwCount - 1)^;
      rid := RtlUlongByteSwap(rid);
      ConvertSidToStringSidA(@sid[0] ,stringsid);
      //if length(strpas(stringsid))>=32 then
      if dwUserCtrl>0 then
            begin
            //writeln(strpas(samname)+':'+inttostr(rid)+':'+strpas(stringsid));

            //87DBA060EB4C302729C00E631A42E6CD
            //writeln(ntid);
            dwlen:= GetColumnData(ntId, @ntHash[0], sizeof(ntHash));
            if dwlen>0 then
              begin
              //write('ntHash:');
              //for c:=0 to sizeof(ntHash)-1 do write(inttohex(ntHash[c],2));
              //writeln;
              DumpHash(rid, @ntHash[0],dwlen);
              end
              else copymemory(@ntHash[0],@empty_nt[0],16);

            //aad3b435b51404eeaad3b435b51404ee
            //writeln(lmId);
            dwlen:= GetColumnData(lmId, @lmHash[0], sizeof(lmHash));
            if dwlen>0 then
              begin
              //write('ntHash:');
              //for c:=0 to sizeof(ntHash)-1 do write(inttohex(ntHash[c],2));
              //writeln;
              DumpHash(rid, @lmHash[0],dwlen);
              end
              else copymemory(@lmHash[0],@empty_lm[0],16);

            write(strpas(samname));
            write(':');
            write(inttostr(rid));
            write(':');
            dumphex('',@lmHash[0],16,false);
            write(':');
            dumphex('',@ntHash[0],16,false);
            write(':::');
            writeln;
            end;
      end;

    end;

    if JetMove(psesid, ptable_id, JET_MoveNext, JET_bitNil) <> JET_errSuccess then break;
    end;

  // close table
  err := JetCloseTable(psesid, ptable_id);

  result:=true;
end;

 //*  + Obtain Pek-List
 //*  + Open datatable
 //*  + Retrieve list and decrypt first key
function GetPEKey(pbSysKey:PBYTE; pbPEKey:PBYTE):BOOL;
var
  pekId:integer ;
  bResult:boolean = FALSE;
  tableId:JET_TABLEID;
  err:JET_API;
  dwPekListSize:dword = 0;
  c:byte;
  //
  output:array[0..511] of byte;
begin
  result:=false;
  try
  //writeln('**** GetPEKey ****');
  pekId:= GetColumnId(ATT_PEK_LIST);
  // need column id at least
  if (pekId = 0) then
    begin
    writeln('pekId = 0');
    exit;
    //exit(false) would be an option in objfpc mode - see https://www.freepascal.org/docs-html/ref/refse94.html
    end;
  //writeln('pekId:'+inttostr(pekId));

  // open the datatable
  err := JetOpenTableA(psesid, pdbid, 'datatable', nil, 0, JET_bitTableReadOnly or JET_bitTableSequential, tableId);
  if err<>0 then raise exception.Create('JetOpenTableA:'+inttohex(err,8)) ;

  // go to first
  err := JetMove(psesid, tableId, JET_MoveFirst, JET_bitNil);
  if err<>0 then raise exception.Create('JetMove:'+inttohex(err,8)) ;

  // while good read
  while (err = JET_errSuccess) do
    begin
    //fillchar(peklist,sizeof(peklist),0);
    fillchar(output,sizeof(output),0);
    dwPekListSize := 0;
    err := JetRetrieveColumn(psesid, tableId, pekId,@output[0], sizeof(output), dwPekListSize, JET_bitNil, nil);

    //dwPekListSize := 0;
    //err := JetRetrieveColumn(psesid, tableId, pekId,@pekList, sizeof(pekList), dwPekListSize, JET_bitNil, nil);
    //if dwPekListSize>0 then writeln('dwPekListSize:'+inttostr(dwPekListSize));

    // ensure it's good read and size exceeds size of PEK_LIST structure
    // skip err checking (win10 returns 1006 err...)
    //if dwPekListSize>0 then writeln(inttostr(dwPekListSize)+':'+inttostr(sizeof(PEK_LIST)));
    if {(err = JET_errSuccess) and} (dwPekListSize >= sizeof(PEK_LIST)) then
      begin
      //dumphex('@output[0]',@output[0],dwPekListSize);
      //writeln('dwPekListSize:'+inttostr(dwPekListSize));
      //writeln('Got something...attempting to decrypt...'+inttostr(dwPekListSize));
      // decrypt the data returned
      // depending on major/minor values in data read
      // a salt may or may not be required
      //dumphex('',@pekList.Hdr,4); //02 00 00 00
      writeln('Version:'+inttostr(output[0]));
      //if pekList.Hdr.dwMajor=2 then
      if output[0]=2 then
      begin
      EncryptDecryptWithKey(pbSysKey, SYSTEM_KEY_LEN,
          @output[8], PEK_SALT_LEN, PEK_SALT_ROUNDS,
          @output[24], dwPekListSize - sizeof(PEK_HDR));
      //copymemory(@pekList.Hdr  ,@output[0],sizeof(PEK_HDR));
      //copymemory(@pekList.Data ,@output[24],dwPekListSize - sizeof(PEK_HDR));
      copymemory(@pekList  ,@output[0],dwPekListSize);
      end;
      //beware after win2012r2, encryption changes and hdr starts with 03 00 00 00
      //# using AES:
      //# Key: the bootKey/syskey
      //# CipherText: PEKLIST_ENC['EncryptedPek']
      //# IV: PEKLIST_ENC['KeyMaterial']
      //if pekList.Hdr.dwMajor=3 then
      if output[0]=3 then
      begin
      //dumphex('syskey',pbSysKey,SYSTEM_KEY_LEN);
      //dumphex('salt',@pekList.Hdr.bSalt[0],PEK_SALT_LEN);
      //dumphex('salt',@output[8],PEK_SALT_LEN);
      //dumphex('data before',@output[24],dwPekListSize - sizeof(PEK_HDR));
      {
      DecryptAes(pbSysKey, SYSTEM_KEY_LEN,
          @pekList.Hdr.bSalt[0], PEK_SALT_LEN,
          @pekList.Data, dwPekListSize - sizeof(PEK_HDR));
      }
      DecryptAes(pbSysKey, SYSTEM_KEY_LEN,
          @output[8], PEK_SALT_LEN,
          @output[24], dwPekListSize - sizeof(PEK_HDR));
      //dumphex('data after',@output[24],dwPekListSize - sizeof(PEK_HDR));
      //copymemory(@pekList.Hdr  ,@output[0],sizeof(PEK_HDR));
      //copymemory(@pekList.Data ,@output[24],dwPekListSize - sizeof(PEK_HDR));
      copymemory(@pekList  ,@output[0],dwPekListSize);
      end;
      // verify our decryption was successful.
      end;

      bResult := comparemem(@pekList.Data.bAuth[0],@PekListAuthenticator[0],PEK_AUTH_LEN) =true;
      if (bResult) then
        begin
        // if good, copy back to buffer
        copymemory(pbPEKey, @pekList.Data.entry, PEK_VALUE_LEN);
        break;
      end;
      //else writeln('bAuth not ok');
    err := JetMove(psesid, tableId, JET_MoveNext, JET_bitNil);
    end;

  // close table
  err := JetCloseTable(psesid, tableId);
  result:=bResult;

  except
    on e:exception do
       begin
         writeln('GetPEKey:'+e.message);
         writeln(JetErrorMessage(err));
       end;
  end;
end;

function enumcolumns():boolean;
var
  tmp:string;
  pcbActual:ulong=0;
  //
  colList:JET_COLUMNLIST;
  info:COLUMN_INFO;
  ret:JET_API;
begin
  //writeln('**** enumcolumns ****');
  result:=false;

  try


  ret:=JetOpenTableA(psesid ,pdbid,'MSysObjects',nil,0,JET_bitTableReadOnly,ptable_id);
  if ret<>0 then raise exception.Create('JetOpenTable:'+inttohex(ret,8)) ;
  //writeln('JetOpenTable');


  ret := JetGetTableColumnInfoA(psesid, ptable_id, nil, @colList,  sizeof(colList), JET_ColInfoListSortColumnid);
  if ret<>0 then raise exception.Create('JetOpenTable:'+inttohex(ret,8)) ;
  //writeln('JetGetTableColumnInfoA');

  ret:=JetMove(psesid, ptable_id, JET_MoveFirst, JET_bitNil);
  if ret<>0 then raise exception.Create('JetMove:'+inttohex(ret,8)) ;
  //writeln('JetMove');

  //lets go thru column names
  while 1=1 do
  begin
  fillchar(info,sizeof(info),0);
  ret:= JetRetrieveColumn(psesid, ptable_id, colList.columnidcolumnname, @info.name[0], sizeof(info.name), pcbActual, JET_bitNil, nil);
  //writeln('JetRetrieveColumn');
  if ret=0 then
     begin
       pcbActual:=0;
       ret:= JetRetrieveColumn(psesid, ptable_id, colList.columnidcoltyp,@info.uColumnId, sizeof(info.uColumnId), pcbActual, JET_bitNil, nil);
       if pos('ATT',info.name)>0 then
          begin
          //writeln(info.name+' '+inttostr(info.uColumnId));
          tmp:=info.name;
          delete(tmp,1,4);
          info.uAttrId := strtoint(tmp);
          SetLength(columns ,length(columns)+1);
          columns[high(columns)] :=info;
          end;
     end;
  ret:=JetMove(psesid, ptable_id, JET_MoveNext,JET_bitNil);
  if ret<>0 then break;
  end;

  ret:=JetCloseTable(psesid,ptable_id );
  if ret<>0 then raise exception.Create('JetCloseTable:'+inttohex(ret,8)) ;
  //writeln('JetCloseTable');

  result:=true;

  except
    on e:exception do
       begin
         writeln('enumcolumns:'+e.message);
         writeln(JetErrorMessage(ret));
       end;
  end;

end;

function close(filename:pchar):boolean;
    var
      ret:JET_API;
begin
  result:=false;
  try
 ret:=JetCloseDatabase(psesid ,pdbid,JET_bitDbReadOnly);
   if ret<>0 then raise exception.Create('JetCloseDatabase:'+inttohex(ret,8)) ;
   //writeln('JetCloseDatabase');

   ret:=JetDetachDatabaseA(psesid ,filename);
   if ret<>0 then raise exception.Create('JetDetachDatabaseA:'+inttohex(ret,8)) ;
   //writeln('JetDetachDatabaseA');

   ret:=JetEndSession(psesid ,0);
   if ret<>0 then raise exception.Create('JetEndSession:'+inttohex(ret,8)) ;
   //writeln('JetEndSession');

   ret:=JetTerm(pinstance ); // also destroys the Instance
   if ret<>0 then raise exception.Create('JetTerm:'+inttohex(ret,8)) ;
   //writeln('JetTerm');

   result:=true;

   except
    on e:exception do
       begin
         writeln('close:'+e.message);
         writeln(JetErrorMessage(ret));
       end;
    end;

end;

function open(filename:pchar):boolean;
var
  ret:JET_API;
begin
  result:=false;
  try
    // set the page size for NTDS.dit
    ret:=JetSetSystemParameterA (pinstance, JET_sesidNil, JET_paramDatabasePageSize, NTDS_PAGE_SIZE, nil);
    if ret<>0 then raise exception.Create('JetSetSystemParameterA:'+inttohex(ret,8)) ;

    // Turn off recovery mode
    ret:=JetSetSystemParameterA (pinstance, JET_sesidNil, JET_paramRecovery, 0, pchar('Off'));
    if ret<>0 then raise exception.Create('JetSetSystemParameterA:'+inttohex(ret,8)) ;

    //https://github.com/microsoft/ManagedEsent/blob/master/EsentInterop/jet_param.cs
    //JET_paramEnableIndexChecking accepts JET_INDEXCHECKING (which is an enum). The values of '0' and '1' have the same meaning as before,
    // but '2' is JET_IndexCheckingDeferToOpenTable, which means that the NLS up-to-date-ness is NOT checked when the database is attached.
    // It is deferred to JetOpenTable(), which may now fail with JET_errPrimaryIndexCorrupted or JET_errSecondaryIndexCorrupted (which
    // are NOT actual corruptions, but instead reflect an NLS sort change).

    //ret:=JetSetSystemParameterA (pinstance, JET_sesidNil, JET_paramEnableIndexChecking, 1, nil);
    //if ret<>0 then raise exception.Create('JetSetSystemParameterA:'+inttohex(ret,8)) ;

    //ret:=JetSetSystemParameterA (pinstance, JET_sesidNil, JET_paramEnableIndexCleanup, 0, nil);
    //if ret<>0 then raise exception.Create('JetSetSystemParameterA:'+inttohex(ret,8)) ;

    ret:=JetCreateInstanceA(pinstance,pchar('test'));
    if ret<>0 then raise exception.Create('JetCreateInstanceA:'+inttohex(ret,8)) ;
    //writeln('JetCreateInstanceA');

    ret:=JetInit(pinstance);
    if ret<>0 then raise exception.Create('JetInit:'+inttohex(ret,8)) ;
    //writeln('JetInit');

    ret:=JetBeginSessionA(pinstance ,psesid,'','');
    if ret<>0 then raise exception.Create('JetBeginSessionA:'+inttohex(ret,8)) ;
    //writeln('JetBeginSessionA');

    //https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/extensible-storage-engine/jetattachdatabase-function.md
    ret:=JetAttachDatabaseA(psesid ,filename,JET_bitDbReadOnly {or JET_bitDbDeleteCorruptIndexes});
    if ret<>0 then raise exception.Create('JetAttachDatabaseA:'+inttohex(ret,8)) ;
    //writeln('JetAttachDatabaseA');

    ret:=JetOpenDatabaseA(psesid ,filename,'',pdbid,JET_bitDbReadOnly);
    if ret<>0 then raise exception.Create('JetOpenDatabaseA:'+inttohex(ret,8)) ;
    //writeln('JetOpenDatabaseA');

  result:=true;

  except
   on e:exception do
      begin
        writeln('open:'+e.message);
        writeln(JetErrorMessage(ret));
      end;
   end;

end;

procedure main;
var
  ret:JET_API;
  pek:array[0..15] of byte;
  mask:TFPUExceptionMask;
  bytes:tbytes;
begin

  //writeln(sizeof(PEK_HDR));  //24
  //writeln(sizeof(PEK_DATA)); //52
  //writeln(sizeof(PEK_LIST)); //76

  if paramcount=0 then
     begin
     writeln('ntdsextract syskey path_to_db');
     exit;
     end;

  if paramcount>=1 then
     begin
     syskey:=HexaStringToByte2(paramstr(1));
     dumphex('syskey',@syskey[0],length(syskey));
     end;

  if paramcount>=2
     then filename:=paramstr(2)
     else filename:='ntds.dit';
 //writeln('start');
     //https://github.com/ANSSI-FR/AD-permissions/blob/master/esent_dump/README
     //"MSysObjects" contains the metadata, "datatable" is the actual AD table, "sd_table" contains the security descriptors

 //loading esent.dll requires the below
 mask:=SetExceptionMask([exInvalidOp, exDenormalized, exZeroDivide, exOverflow, exUnderflow, exPrecision]);

 try

 if open(pchar(filename))=true then
 begin


  // ******************************************
  // *********** do something *****************
  //at this stage we can : opentable, RetrieveColumn, closetable

  if enumcolumns=true then
     begin
     //writeln('enumcolumns:ok') ;

     //PEK # 0 found and decrypted: a41c345f5469862fa30a0bd35f29f656
     if GetPEKey(@syskey[0],@pek[0])=true then
        begin
        dumphex('pek',@pek[0],sizeof(pek));
        //dumphex('pek',@pekList.Data.entry[0] ,sizeof(PEK_DATA_ENTRY));
        GetHashes (false,false,false);
        end
        else writeln('GetPEKey failed');
     end
     else writeln('enumcolumns failed');

  // ******************************************
  // ******************************************


 close(pchar(filename));
 end; //if open('ntds.dit')=false then

 except
   on e:exception do
      begin
        writeln('main:'+e.message);
        writeln(JetErrorMessage(ret));
      end;
 end;

  //reseting ExceptionMask
 SetExceptionMask(mask);
end;

begin
  main;
end.

