//https://www.emmet-gray.com/Articles/ESE.html
//https://github.com/danmar/clang-headers/blob/master/esent.h
//https://github.com/leecher1337/jetiisam/blob/master/esent.h

//{$OPTIMIZATION LEVEL1}

unit esent;

//{$mode objfpc}{$H+}
//{$mode delphi}

interface

uses windows,sysutils;

const
  JET_errSuccess=0;
  JET_bitDbReadOnly=  $00000001;
  //JET_bitDbDeleteCorruptIndexes
  //->If JET_paramEnableIndexChecking has been set, all indexes over Unicode data will be deleted. See the Remarks section for more details.
  //JET_bitDbDeleteUnicodeIndexes
  //->All indexes over Unicode data will be deleted, regardless of the setting of JET_paramEnableIndexChecking. See the Remarks section for more details.
  JET_bitDbDeleteCorruptIndexes=$10;
  JET_bitDbDeleteUnicodeIndexes=$00000400;
  JET_bitTableReadOnly=  $00000004;
  JET_paramErrorToString=  70;
  JET_sesidNil=0;
  JET_paramDatabasePageSize=  64;
  JET_paramRecovery=  34;
  JET_paramEnableIndexChecking = 45;
  JET_paramEnableIndexCleanup = 54;
  JET_ColInfoListSortColumnid=7;
  JET_MoveFirst= $80000000;
  JET_MoveNext=1;
  JET_cbNameMost=64; //128 if unicode
  JET_bitTableSequential=  $00008000;

type
JET_API = nativeuint;
JET_API_PTR = nativeuint; //pointer; //int64/ulong or nativeuint ?
JET_HANDLE=JET_API_PTR;
JET_INSTANCE=JET_API_PTR;
JET_SESID=JET_API_PTR;
JET_TABLEID=JET_API_PTR;
JET_PCSTR=pchar;
JET_PCWSTR=pwidechar;
JET_PSTR=pchar;
JET_PWSTR=pwidechar;
JET_GRBIT=ulong;
JET_DBID=ulong;
JET_COLUMNID =ulong;

const JET_bitNil:JET_GRBIT=0;

type JET_RETINFO =record
  cbStruct:ulong;
  ibLongValue:ulong;
  itagSequence:ulong;
  columnidNextTagged:JET_COLUMNID;
end;
PJET_RETINFO=^JET_RETINFO;

type JET_COLUMNLIST =record
  cbStruct:ulong;
  tableid:JET_TABLEID;
  cRecord:ulong;
  columnidPresentationOrder:JET_COLUMNID;
  columnidcolumnname:JET_COLUMNID;
  columnidcolumnid:JET_COLUMNID;
  columnidcoltyp:JET_COLUMNID;
  columnidCountry:JET_COLUMNID;
  columnidLangid:JET_COLUMNID;
  columnidCp:JET_COLUMNID;
  columnidCollate:JET_COLUMNID;
  columnidcbMax:JET_COLUMNID;
  columnidgrbit:JET_COLUMNID;
  columnidDefault:JET_COLUMNID;
  columnidBaseTableName:JET_COLUMNID;
  columnidBaseColumnName:JET_COLUMNID;
  columnidDefinitionName:JET_COLUMNID;
end;
PJET_COLUMNLIST=^JET_COLUMNLIST;

type COLUMN_INFO =record
  name:array [0..JET_cbNameMost] of char;   // column name
  uColumnId:ULONG;
  uAttrId:ULONG;
end;
PCOLUMN_INFO=^COLUMN_INFO;

//Function JetCreateInstanceA(var pinstance:JET_INSTANCE;szInstanceName : pchar) : JET_API; stdcall; external 'esent.dll';
//Function JetInit(var pinstance:JET_INSTANCE): JET_API; stdcall; external 'esent.dll';
//Function JetBeginSessionA(instance:JET_INSTANCE;var psesid:JET_SESID;szUserName:JET_PCSTR;szPassword:JET_PCSTR): JET_API; stdcall; external 'esent.dll';
//Function JetAttachDatabaseA(sesid:JET_SESID;szFilename:pchar;grbit:JET_GRBIT): JET_API; stdcall; external 'esent.dll';
//Function JetOpenDatabaseA(sesid:JET_SESID;szFilename:pchar;szConnect:pchar;var pdbid:JET_DBID;grbit:JET_GRBIT): JET_API; stdcall; external 'esent.dll';
//Function JetOpenTable(sesid:JET_SESID;dbid:JET_DBID;szTableName:pchar;pvParameters:pvoid;cbParameters:ulong;grbit:JET_GRBIT;var ptableid:JET_TABLEID): JET_API; stdcall; external 'esent.dll';
//Function JetGetTableColumnInfoA(sesid:JET_SESID;tableid:JET_TABLEID;szColumnName:pchar;pvResult:pointer;cbMax:ulong;InfoLevel:ulong): JET_API; stdcall; external 'esent.dll';
//Function JetRetrieveColumn(sesid:JET_SESID;tableid:JET_TABLEID;columnid:JET_COLUMNID;pvData:pvoid;cbData:ulong;var pcbActual:ulong;grbit:JET_GRBIT;pretinfo:PJET_RETINFO): JET_API; stdcall; external 'esent.dll';
//Function JetMove(sesid:JET_SESID;tableid:JET_TABLEID;cRow:long;grbit:JET_GRBIT): JET_API; stdcall; external 'esent.dll';
//Function JetCloseTable(sesid:JET_SESID;tableid:JET_TABLEID): JET_API; stdcall; external 'esent.dll';
//Function JetCloseDatabase(sesid:JET_SESID;dbid:JET_DBID;grbit:JET_GRBIT): JET_API; stdcall; external 'esent.dll';
//Function JetDetachDatabaseA(sesid:JET_SESID;szFilename:pchar): JET_API; stdcall; external 'esent.dll';
//Function JetEndSession(sesid:JET_SESID;grbit:JET_GRBIT): JET_API; stdcall; external 'esent.dll';
//Function JetTerm(instance:JET_INSTANCE ): JET_API; stdcall; external 'esent.dll';
//Function JetGetSystemParameterA(instance:JET_INSTANCE;sesid:JET_SESID;paramid:ulong;var plParam:JET_API_PTR;szParam:JET_PSTR;cbMax:ulong): JET_API; stdcall; external 'esent.dll';
//Function JetSetSystemParameterA(var pinstance:JET_INSTANCE;sesid:JET_SESID;paramid:ulong;lParam:JET_API_PTR;szParam:JET_PCSTR): JET_API; stdcall; external 'esent.dll';


function GetColumnData(columnId:ULONG; pbBuffer:PVOID; cbBufSize:DWORD):DWORD ;
function GetColumnId(uAttrId:ULONG):ulong;
Function JetErrorMessage(error_code:JET_API ):string;



var
    filename:string;
    pinstance:JET_INSTANCE=0;
    psesid:JET_SESID=0 ;
    pdbid:JET_DBID=0 ;
    ptable_id:JET_TABLEID=0 ;
    //
    columns:array of COLUMN_INFO;
    //
    JetCreateInstanceA:Function(var pinstance:JET_INSTANCE;szInstanceName : pchar) : JET_API; stdcall;
    JetInit:Function(var pinstance:JET_INSTANCE): JET_API; stdcall;
    JetBeginSessionA:Function(instance:JET_INSTANCE;var psesid:JET_SESID;szUserName:JET_PCSTR;szPassword:JET_PCSTR): JET_API; stdcall;
    JetAttachDatabaseA:Function(sesid:JET_SESID;szFilename:pchar;grbit:JET_GRBIT): JET_API; stdcall;
    JetOpenDatabaseA:Function (sesid:JET_SESID;szFilename:pchar;szConnect:pchar;var pdbid:JET_DBID;grbit:JET_GRBIT): JET_API; stdcall;
    JetOpenTableA:Function(sesid:JET_SESID;dbid:JET_DBID;szTableName:pchar;pvParameters:pvoid;cbParameters:ulong;grbit:JET_GRBIT;var ptableid:JET_TABLEID): JET_API; stdcall;
    JetGetTableColumnInfoA:Function(sesid:JET_SESID;tableid:JET_TABLEID;szColumnName:pchar;pvResult:pointer;cbMax:ulong;InfoLevel:ulong): JET_API; stdcall;
    JetRetrieveColumn:Function(sesid:JET_SESID;tableid:JET_TABLEID;columnid:JET_COLUMNID;pvData:pvoid;cbData:ulong;var pcbActual:ulong;grbit:JET_GRBIT;pretinfo:PJET_RETINFO): JET_API; stdcall;
    JetMove:Function(sesid:JET_SESID;tableid:JET_TABLEID;cRow:long;grbit:JET_GRBIT): JET_API; stdcall;
    JetCloseTable:Function(sesid:JET_SESID;tableid:JET_TABLEID): JET_API; stdcall;
    JetCloseDatabase:Function(sesid:JET_SESID;dbid:JET_DBID;grbit:JET_GRBIT): JET_API; stdcall;
    JetDetachDatabaseA:Function(sesid:JET_SESID;szFilename:pchar): JET_API; stdcall;
    JetEndSession:Function(sesid:JET_SESID;grbit:JET_GRBIT): JET_API; stdcall;
    JetTerm:Function(instance:JET_INSTANCE ): JET_API; stdcall;
    JetGetSystemParameterA:Function(instance:JET_INSTANCE;sesid:JET_SESID;paramid:ulong;var plParam:JET_API_PTR;szParam:JET_PSTR;cbMax:ulong): JET_API; stdcall;
    JetSetSystemParameterA:Function(var pinstance:JET_INSTANCE;sesid:JET_SESID;paramid:ulong;lParam:JET_API_PTR;szParam:JET_PCSTR): JET_API; stdcall;

implementation

var
 lib: THandle = 0;

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

function GetColumnData(columnId:ULONG; pbBuffer:PVOID; cbBufSize:DWORD):DWORD ;
var
  err:JET_API;
  dwSize:DWORD = 0;
begin
  ZeroMemory(pbBuffer, cbBufSize);
  err := JetRetrieveColumn(psesid, ptable_id , columnId,pbBuffer, cbBufSize, dwSize, JET_bitNil, nil);
  //if err<>0 then writeln(JetErrorMessage(err));
  result:= dwSize;
end;

Function JetErrorMessage(error_code:JET_API ):string;
var
    msg:pchar;
    ret:JET_API;
begin
    msg:=AllocMem (256);
    ret := JetGetSystemParameterA(0, 0, JET_paramErrorToString, error_code, msg, 256);
    If ret <> 0
       Then result:=inttostr(error_code)
       else result:=msg;
End;

function InitAPI: Boolean;
begin
Result := False;
if Win32Platform <> VER_PLATFORM_WIN32_NT then Exit;
if lib = 0 then lib := LoadLibrary('esent.dll');
if lib > HINSTANCE_ERROR then
begin
  JetCreateInstanceA := GetProcAddress(lib, 'JetCreateInstanceA');
  JetInit:= GetProcAddress(lib, 'JetInit');
  JetBeginSessionA:= GetProcAddress(lib, 'JetBeginSessionA');
  JetAttachDatabaseA:= GetProcAddress(lib, 'JetAttachDatabaseA');
  JetOpenDatabaseA:= GetProcAddress(lib, 'JetOpenDatabaseA');
  JetOpenTableA:= GetProcAddress(lib, 'JetOpenTableA');
  JetGetTableColumnInfoA:= GetProcAddress(lib, 'JetGetTableColumnInfoA');
  JetRetrieveColumn:= GetProcAddress(lib, 'JetRetrieveColumn');
  JetMove:= GetProcAddress(lib, 'JetMove');
  JetCloseTable:= GetProcAddress(lib, 'JetCloseTable');
  JetCloseDatabase:= GetProcAddress(lib, 'JetCloseDatabase');
  JetDetachDatabaseA:= GetProcAddress(lib, 'JetDetachDatabaseA');
  JetEndSession:= GetProcAddress(lib, 'JetEndSession');
  JetTerm:= GetProcAddress(lib, 'JetTerm');
  JetGetSystemParameterA:= GetProcAddress(lib, 'JetGetSystemParameterA');
  JetSetSystemParameterA:= GetProcAddress(lib, 'JetSetSystemParameterA');
  Result := True;
end;
end;

procedure FreeAPI;
begin
  if lib <> 0 then FreeLibrary(lib);
  lib := 0;
end;

initialization InitAPI;
finalization FreeAPI;

end.

