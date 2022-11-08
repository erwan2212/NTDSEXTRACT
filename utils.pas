unit utils;

{$mode delphi}

interface

  uses SysUtils;

 function HexaStringToByte2(hash:string):tbytes;

 function ByteSwap32(dw: cardinal): cardinal;

  (*

    Ror and Rol Function provided at

    https://forum.tuts4you.com/topic/23701-bitwise-rotation-with-cc-and-delphi/?p=172694

    Improved and reposted by yours truly.

  *)

  function Ror(Value: Byte; N: Integer): Byte; overload;

  function Rol(Value: Byte; N: Integer): Byte; overload;

  function Ror(Value: ShortInt; N: Integer): ShortInt; overload;

  function Rol(Value: ShortInt; N: Integer): ShortInt; overload;



  function Ror(Value: Word; N: Integer): Word; overload;

  function Rol(Value: Word; N: Integer): Word; overload;

  function Ror(Value: SmallInt; N: Integer): SmallInt; overload;

  function Rol(Value: SmallInt; N: Integer): SmallInt; overload;



  function Ror(Value: LongWord; N: Integer): LongWord; overload;

  function Rol(Value: LongWord; N: Integer): LongWord; overload;

  function Ror(Value: Integer; N: Integer): Integer; overload;

  function Rol(Value: Integer; N: Integer): Integer; overload;



  function Ror(Value: UInt64; N: Integer): UInt64; overload;

  function Rol(Value: UInt64; N: Integer): UInt64; overload;

  function Ror(Value: Int64; N: Integer): Int64; overload;

  function Rol(Value: Int64; N: Integer): Int64; overload;



implementation


procedure log(msg:string);
begin
//nothing for now
end;

function HexaStringToByte2(hash:string):tbytes;
var
  i:word;
  tmp:string;
  b:longint;
begin
log('**** HexaStringToByte2 ****');
log('length:'+inttostr(length(hash)));
try
i:=1;
//log('hash:'+hash);
//log('length(hash) div 2:'+inttostr(length(hash) div 2));
setlength(result,length(hash) div 2);
  while I<length(hash) do
      begin
      tmp:=copy(hash,i,2);
      if TryStrToInt ('$'+tmp,b) then result[i div 2]:=b;
      //result[i div 2]:=strtoint('$'+tmp);
      inc(i,2);
      end;
except
on e:exception do log('HexaStringToByte2:'+e.Message );
end;
end;


function Ror(Value: Byte; N: Integer): Byte; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: Byte; N: Integer): Byte; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;



function Ror(Value: ShortInt; N: Integer): ShortInt; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: ShortInt; N: Integer): ShortInt; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;



function Ror(Value: Word; N: Integer): Word; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: Word; N: Integer): Word; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;



function Ror(Value: SmallInt; N: Integer): SmallInt; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: SmallInt; N: Integer): SmallInt; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;





function Ror(Value: LongWord; N: Integer): LongWord; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: LongWord; N: Integer): LongWord; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;



function Ror(Value: Integer; N: Integer): Integer; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: Integer; N: Integer): Integer; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;



function Ror(Value: UInt64; N: Integer): UInt64; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: UInt64; N: Integer): UInt64; overload;

begin

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;



function Ror(Value: Int64; N: Integer): Int64; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shr N) or (Value shl ((SizeOf(Value)*8)-n));

end;



function Rol(Value: Int64; N: Integer): Int64; overload;

begin

  N := N mod (SizeOf(Value)*8);

  Result := (Value shl N) or (Value shr ((SizeOf(Value)*8)-n));

end;


function ByteSwap32(dw: cardinal): cardinal;
asm
  {$IFDEF CPUX64}
  mov rax, rcx
  {$ENDIF}
  bswap eax
end;

end.

