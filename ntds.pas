//https://github.com/mubix/ntds_decode/blob/master/ntds.cpp
//https://github.com/zcgonvh/NTDSDumpEx/blob/master/NTDSDumpEx/ntds.cpp

//{$OPTIMIZATION LEVEL1}

unit ntds;

//{$mode delphi}

interface

uses
  windows,JwaWinCrypt,sysutils,utils;

const
   PEK_SALT_LEN=  16;
   PEK_AUTH_LEN=  16;
   PEK_VALUE_LEN= 16;
   PEK_SALT_ROUNDS= 1000;

   SYSTEM_KEY_LEN= 16;

  SECRET_CRYPT_TYPE_RC4=$11;
  SECRET_CRYPT_TYPE_AES=$13;

NTDS_PAGE_SIZE= 8192;

ATT_PEK_LIST=590689;    // pekList
ATT_USER_ACCOUNT_CONTROL= 589832;    // userAccountControl
ATT_OBJECT_SID=589970;    // objectSid
ATT_DBCS_PWD=589879;    // dBCSPwd
ATT_UNICODE_PWD=589914;    // unicodePwd
ATT_SAM_ACCOUNT_NAME=590045;    // sAMAccountName
ATT_DESCRIPTION=13;    // description
ATT_HOME_DIRECTORY=589868;    // homeDirectory
ATT_LM_PWD_HISTORY=589984;    // lmPwdHistory
ATT_NT_PWD_HISTORY=589918;    // ntPwdHistory
ATT_USER_PRINCIPAL_NAME = 590480;

 ATT_SURNAME				=4;
 ATT_GIVEN_NAME			=42;
 ATT_ORG_UNIT			=11;

 ATT_DISPLAY_NAME		=131085;
 ATT_COMMENT				=131153;
 ATT_DOMAIN				=1376281;
 ATT_PRINCIPAL			=590480;
 ATT_MAIL                       =1376259;
 ATT_TELEPHONE_NUMBER           =20;


 ATT_LAST_LOGON_INDEX =589876;
 ATT_LAST_LOGON_TIME_STAMP_INDEX =591520;
 ATT_ACCOUNT_EXPIRES_INDEX =589983;
 ATT_PASSWORD_LAST_SET_INDEX =589920;
 ATT_BAD_PWD_TIME_INDEX =589873;
 ATT_LOGON_COUNT_INDEX =589993;
 ATT_BAD_PWD_COUNT_INDEX =589836;


ADS_UF_NORMAL_ACCOUNT= 512;      // 0x200

 //bType: BYTE;  bVersion: BYTE; reserved: WORD;  aiKeyAlg: ALG_ID;
 //CALG_DES	0x00006601
 header: array [0..7] of byte = ($08, $02, $00, $00, $01, $66, $00, $00);
 PekListAuthenticator :array[0..PEK_AUTH_LEN-1] of byte= ( $56, $D9, $81, $48, $EC, $91, $D1, $11,  $90, $5A, $00, $C0, $4F, $C2, $D4, $CF);

type PEK_HDR =record
   dwMajor:DWORD;             // either 1 or 2
   dwMinor:DWORD;             // possibly inaccurate description
   bSalt:array [0..PEK_SALT_LEN-1] of byte;  // added with version 2
end;
PPEK_HDR=^PEK_HDR;

type PEK_DATA_ENTRY=record
	 //dwIndex:DWORD;             //index
	 bKey:array [0..PEK_VALUE_LEN-1] of byte;  //data
end;
PPEK_DATA_ENTRY=^PEK_DATA_ENTRY;

// unknown1 and unknown2 are used but I haven't investigated
// since the key probably doesn't get changed much
//{$align 8}
type PEK_DATA =record
  bAuth:array [0..PEK_AUTH_LEN-1] of byte;  // verifies if decryption successful
  ftModified:FILETIME; //int64;      // when list was last changed
  //time1,time2:dword;
  //time:uint64;
  dwUnknown1:DWORD;          //
  dwTotalKeys:DWORD;         // total keys in list
  dwUnknown2:DWORD;          //
  //bKey:array [0..PEK_VALUE_LEN-1] of byte;  // list can support multiple keys but it's not supported here at the moment.
  entry:array[0..0] of PEK_DATA_ENTRY ;
end;

type PEK_LIST =record
   Hdr:PEK_HDR;
   Data:PEK_DATA;
end;
  PPEK_LIST=^PEK_LIST ;

  type DES_KEY_BLOB =record
     Hdr:BLOBHEADER;
     dwKeySize:DWORD;
     rgbKeyData:array [0..7] of byte;
  end;

    // There appears to be variations or revisions with this
    // specific structure more than others.
    // I've only studied Windows 2003/2008 server
    //
    // Seems to work fine with those . . .
    //
    type SECRET_DATA =record
       wVersion:WORD;             //
       wUnknown:WORD;             // seems reserved
       dwPEKIndex:DWORD;          // key index for PEK_LIST
       bSalt:array [0..PEK_SALT_LEN-1] of byte;  // RtlGenRandom();
       //pbData:array [0..0] of BYTE;
       pbData: array [0..15] of BYTE;
    end;
      PSECRET_DATA=^SECRET_DATA;

    type AES128_KEY_BLOB=record
	hdr:BLOBHEADER;
	dwKeySize:DWORD;
	bKey:array [0..15] of byte;
    end;
    PAES128_KEY_BLOB=^AES128_KEY_BLOB;

var
  pekList:PEK_LIST;            // size might exceed structure

function IsAccountMachine(dwUserCtrl:DWORD):bool;

function EncryptDecryptWithKey(pbKey:PBYTE; dwKeyLen:DWORD;
  pbSalt:PBYTE; dwSaltLen:DWORD; dwSaltRounds:DWORD;
  pbData:PBYTE; dwDataLen:DWORD):boolean;

function DecryptAes128(pbKey:PBYTE;dwKeyLen:DWORD;
	pbSalt:PBYTE; dwSaltLen:DWORD;
	pbData:PBYTE; dwDataLen:DWORD):boolean;

procedure DumpHash(rid:DWORD; pbHash:PBYTE;dwlen:dword);

function dumphex(description:string;bytes:lpbyte;len:byte;bcrlf:boolean=true):string;


implementation

function IsAccountMachine(dwUserCtrl:DWORD):bool;
begin
  if (dwUserCtrl and ADS_UF_NORMAL_ACCOUNT) = 0 then
    begin
    result:= TRUE;
    end;
  result:= FALSE;
end;

function DecryptAes128(pbKey:PBYTE;dwKeyLen:DWORD;
	pbSalt:PBYTE; dwSaltLen:DWORD;
	pbData:PBYTE; dwDataLen:DWORD):boolean;
const
MS_ENH_RSA_AES_PROV:pchar{$ifdef fpc}='Microsoft Enhanced RSA and AES Cryptographic Provider'+#0{$endif fpc};
PROV_RSA_AES = 24;
CALG_AES    =	$00006611;
CALG_AES_128=	$0000660e;
CALG_AES_256=	$00006610;
CRYPT_MODE_CBC= 1;
CRYPT_MODE_ECB= 2;
var
	hProv:HCRYPTPROV=0;
	hKey:HCRYPTKEY=0;
	blob:AES128_KEY_BLOB;
	bResult:BOOL = FALSE;
	d:DWORD;
        dwKeyCypherMode:dword;
        //output:tbytes;
begin
  result:=false;
  fillchar(blob,0,sizeof(blob));
  d:= dwDataLen;
	if CryptAcquireContext(hProv, nil, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
		CRYPT_NEWKEYSET or CRYPT_VERIFYCONTEXT) then
        begin
		blob.hdr.bType := PLAINTEXTKEYBLOB;
		blob.hdr.bVersion := CUR_BLOB_VERSION;
		blob.hdr.reserved := 0;
		blob.hdr.aiKeyAlg := CALG_AES_128;
		blob.dwKeySize := dwKeyLen;  //16
		copymemory(@blob.bKey[0], pbKey, dwKeyLen); //16
                //dumphex('key',@blob.bKey[0],blob.dwKeySize);
                //dumphex('salt',pbSalt,dwSaltLen);
		if CryptImportKey(hProv, @blob, sizeof(AES128_KEY_BLOB), 0, 0, hKey) then
		begin
                        if CryptSetKeyParam(hKey, KP_IV, pbSalt, 0)
                         then bResult:=CryptDecrypt(hKey, 0, false, 0, pbdata, d);
                //writeln('datalen:'+inttostr(d));
                //writeln(bResult);
                //dumphex('output',@output[0],d);
		end;
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
	end;
	result:= bResult;
end;

//*  Generate System key from pass phrase -> level 2
 //*  Derives 128-bit value from MD5
function EncryptDecryptWithKey(pbKey:PBYTE; dwKeyLen:DWORD;
  pbSalt:PBYTE; dwSaltLen:DWORD; dwSaltRounds:DWORD;
  pbData:PBYTE; dwDataLen:DWORD):boolean;
var
  hProv:HCRYPTPROV;
  hHash:HCRYPTHASH;
  hKey:HCRYPTKEY;
  bResult:BOOL = FALSE;
  i:DWORD=0;
begin
  if (CryptAcquireContext(hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) then
    begin
    if (CryptCreateHash(hProv, CALG_MD5, 0, 0, hHash)) then
      begin
      // first, the key
      CryptHashData(hHash, pbKey, dwKeyLen, 0);

      // now the salt
      for i := 0 to dwSaltRounds-1 do
      begin
        CryptHashData(hHash, pbSalt, dwSaltLen, 0);
      end;
      // get an RC4 key
      if (CryptDeriveKey(hProv, CALG_RC4, hHash, $00800000, hKey)) then
      begin
        // decrypt or encrypt..RC4 is a stream cipher so it doesn't matter
        bResult := CryptEncrypt(hKey, 0, TRUE, 0, pbData, dwDataLen, dwDataLen);
        //writeln(dwDataLen);
        CryptDestroyKey(hKey);
      end;
      CryptDestroyHash(hHash);
    end;
    CryptReleaseContext(hProv, 0);
  end;
  result:= bResult;
end;

function dumphex(description:string;bytes:lpbyte;len:byte;bcrlf:boolean=true):string;
var
  c:byte;
  tmp:string='';
begin
  result:='';
  if description<>'' then write(description+':');
  for c:=0 to len-1 do tmp:=tmp+(inttohex(bytes[c],2));
  result:=tmp;
  if bcrlf=true then writeln(tmp) else write(tmp);
end;

function transformKey(InputKey:tbytes):tbytes;
var
  OutputKey:array [0..7] of char;
  i:byte;
begin
  try
    //# Section 5.1.3
    //OutputKey = []
    OutputKey[0]:=(chr(ord(InputKey[0]) shr $01) );
    OutputKey[1]:= (chr(((ord(InputKey[0]) and $01) shl 6) or (ord(InputKey[1]) shr 2)) );
    OutputKey[2]:= (chr(((ord(InputKey[1]) and $03) shl 5) or (ord(InputKey[2]) shr 3)) );
    OutputKey[3]:= (chr(((ord(InputKey[2]) and $07) shl 4) or (ord(InputKey[3]) shr 4)) );
    OutputKey[4]:= (chr(((ord(InputKey[3]) and $0F) shl 3) or (ord(InputKey[4]) shr 5)) );
    OutputKey[5]:= (chr(((ord(InputKey[4]) and $1F) shl 2) or (ord(InputKey[5]) shr 6)) );
    OutputKey[6]:= (chr(((ord(InputKey[5]) and $3F) shl 1) or (ord(InputKey[6]) shr 7)) );
    OutputKey[7]:= (chr(ord(InputKey[6]) and $7F) );


    for i :=0 to 7 do
        OutputKey[i] := chr((ord(OutputKey[i]) shl 1) and $fe);

    setlength(result,sizeof(OutputKey));
    copymemory(@result[0],@OutputKey [0],sizeof(OutputKey));

          except
          on e:exception do writeln('transformKey:'+e.Message )
          end;
end;



function deriveKey(baseKey:dword;pkey1, pkey2:LPBYTE):tbytes;
var
  //key1,key2:array[0..6] of byte;
  key1,key2:array of byte;
  key:array[0..3] of byte;
  transformed1,transformed2:array of byte;
begin
  try
        //# 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        //# Let I be the little-endian, unsigned integer.
        //# Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        //# Note that because I is in little-endian byte order, I[0] is the least significant byte.
        //# Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        //# Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        //key = pack('<L',baseKey)
        //basekey := {ByteSwap32} (basekey); //we swapped it already !
        fillchar(key,4,0);
        copymemory(@key[0],@basekey,sizeof(dword));

        //dumphex('basekey',@basekey,sizeof(basekey));
        //dumphex('key',@key[0],sizeof(key));

        setlength(key1,7);
        setlength(key2,7);
        key1[0] := key[0]; key1[1] := key[1]; key1[2] := key[2]; key1[3] := key[3]; key1[4] :=key[0] ; key1[5] := key[1] ; key1[6] := key[2];
        key2[0] := key[3]; key2[1] := key[0]; key2[2] := key[1]; key2[3] := key[2]; key2[4] :=key[3] ; key2[5] := key[0] ; key2[6] := key[1];
        //
        //dumphex('key1',@key1[0],sizeof(key1));
        //dumphex('key2',@key2[0],sizeof(key2));

        setlength(transformed1,8);
        transformed1:=transformKey(tbytes(key1));
        CopyMemory(pkey1,@transformed1[0],sizeof(transformed1));

        setlength(transformed2,8);
        transformed2:=transformKey(tbytes(key2));
        CopyMemory(pkey2,@transformed2[0],sizeof(transformed2));


          except
          on e:exception do writeln('deriveKey:'+e.Message )
          end;
end;



//*  Very similar to SAM encryption
procedure decryptHash(rid:DWORD; pbIn, pbOut:LPBYTE);
var
  dwDataLen:DWORD;

  hProv:HCRYPTPROV;
  hKey1, hKey2:HCRYPTKEY;

  Blob1, Blob2:DES_KEY_BLOB;

begin
  try
  if CryptAcquireContext(hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
  begin
    fillchar(Blob1,sizeof(DES_KEY_BLOB),0);
    fillchar(Blob2,sizeof(DES_KEY_BLOB),0);
    // initialize keys
    //dumphex('rid',@rid,sizeof(rid));
    deriveKey (rid,@Blob1.rgbKeyData[0], @Blob2.rgbKeyData[0]);


    //dumphex('Blob1.rgbKeyData',@Blob1.rgbKeyData[0],sizeof(Blob1.rgbKeyData));
    //dumphex('Blob2.rgbKeyData',@Blob2.rgbKeyData[0],sizeof(Blob2.rgbKeyData));

    Blob1.dwKeySize := 8;
    Blob2.dwKeySize := 8;

    copymemory(@Blob1.Hdr, @header[0], 8);
    copymemory(@Blob2.Hdr, @header[0], 8);

    // import keys
    CryptImportKey(hProv, @Blob1, sizeof(Blob1),0, CRYPT_EXPORTABLE, hKey1);

    CryptImportKey(hProv, @Blob2, sizeof(Blob2),0, CRYPT_EXPORTABLE, hKey2);

    dwDataLen := 8;
    CryptDecrypt(hKey1, 0, TRUE, 0, pbIn, dwDataLen);
    copymemory(pbOut, pbIn, 8);

    dwDataLen := 8;
    CryptDecrypt(hKey2, 0, TRUE, 0, pointer(nativeuint(pbIn)+8), dwDataLen);
    copymemory(pointer(nativeuint(pbOut)+8), pointer(nativeuint(pbIn)+8), 8);

    CryptDestroyKey(hKey2);
    CryptDestroyKey(hKey1);

    CryptReleaseContext(hProv, 0);
end;

  except
    on e:exception do writeln('decryptHash:'+e.Message )
  end;

end;

////receiving the encrypted hash (nt / lm) from the table
procedure DecryptSecret(rid:DWORD; pbHash:PBYTE;dwlen:dword);
var
  pSecret:PSECRET_DATA;
  hash:array [0..15] of byte;
  bret:boolean;
  offset:byte=0;
begin
  try
  pSecret := PSECRET_DATA(pbHash);

  //https://cmdjunkie.livejournal.com/27684.html

  //layer 1 was the retrieval/decrypting of the PEK

  //layer 2 remove the RC4 encryption layer - using PEK from layer 1 and encrypted hash
  //writeln('pSecret.wVersion:'+inttostr(pSecret.wVersion));
  if pSecret.wVersion=SECRET_CRYPT_TYPE_RC4
     then bret:=EncryptDecryptWithKey(@pekList.Data.entry, PEK_VALUE_LEN, @pSecret.bSalt[0],
                               PEK_SALT_LEN, 1, @pSecret.pbData[0], dwlen-sizeof(PEK_HDR)); //40-24
  if pSecret.wVersion=SECRET_CRYPT_TYPE_AES then
     begin
     offset:=4;
     bret:=DecryptAes128(@pekList.Data.entry, PEK_VALUE_LEN, @pSecret.bSalt[0],
                               PEK_SALT_LEN, @pSecret.pbData[offset], dwlen - sizeof(PEK_HDR)-offset); //60-24
     end;
  //writeln(bret);
  //verified OK
  //dumphex('pSecret.pbData',@pSecret.pbData[0],sizeof(pSecret.pbData));

  //layer 3 remove the DES encryption layer - using pSecret.pbData from layer 2
  //dumphex('rid',@rid,sizeof(rid));
  decryptHash(rid, @pSecret.pbData[offset], @hash[0]);
  //verified OK
  //dumphex('pSecret.pbData',@hash[0],sizeof(hash));
  copymemory(pbHash, @hash[0], 16);
    except
    on e:exception do writeln('DecryptSecret:'+e.Message )
  end;
end;

//receiving the encrypted hash (nt / lm) from the table
procedure DumpHash(rid:DWORD; pbHash:PBYTE;dwlen:dword);
begin
  try
  //dumphex('',pbhash,dwlen,true) ;
  //dumphex('rid',@rid,sizeof(rid));
  DecryptSecret(rid, pbHash,dwlen);

  //dumphex('pbhash',@pbhash[0],16) ;

  except
    on e:exception do writeln('DumpHash:'+e.Message )
  end;
end;

end.

