program DefenderCheck;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils;

type
  TScanResult = (
    NoThreatFound,
    ThreatFound,
    FileNotFound,
    Timeout,
    ScanError
  );

function RunProcessCapture(const CommandLine: string;
  TimeoutMS: Cardinal;
  out ExitCode: Cardinal;
  out Output: string): Boolean;
var
  SA: TSecurityAttributes;
  StdOutRead, StdOutWrite: THandle;
  SI: TStartupInfoW;
  PI: TProcessInformation;
  Buffer: array[0..4095] of Byte;
  BytesRead: DWORD;
  WaitRes: DWORD;
begin
  Result := False;
  Output := '';
  ExitCode := 0;

  ZeroMemory(@SA, SizeOf(SA));
  SA.nLength := SizeOf(SA);
  SA.bInheritHandle := True;

  if not CreatePipe(StdOutRead, StdOutWrite, @SA, 0) then
    Exit;

  try
    ZeroMemory(@SI, SizeOf(SI));
    SI.cb := SizeOf(SI);
    SI.dwFlags := STARTF_USESTDHANDLES;
    SI.hStdOutput := StdOutWrite;
    SI.hStdError := StdOutWrite;

    ZeroMemory(@PI, SizeOf(PI));

    if not CreateProcessW(
      nil,
      PWideChar(CommandLine),
      nil,
      nil,
      True,
      CREATE_NO_WINDOW,
      nil,
      nil,
      SI,
      PI) then
      Exit;

    CloseHandle(StdOutWrite);

    try
      WaitRes := WaitForSingleObject(PI.hProcess, TimeoutMS);

      if WaitRes = WAIT_TIMEOUT then
      begin
        TerminateProcess(PI.hProcess, 1);
        ExitCode := Cardinal(-1);
        Exit;
      end;

      GetExitCodeProcess(PI.hProcess, ExitCode);

      while ReadFile(StdOutRead, Buffer, SizeOf(Buffer), BytesRead, nil) and
  (BytesRead > 0) do
begin
  SetString(Output, PAnsiChar(@Buffer[0]), BytesRead);
  Output := Output;
end;

      Result := True;

    finally
      CloseHandle(PI.hProcess);
      CloseHandle(PI.hThread);
    end;

  finally
    CloseHandle(StdOutRead);
  end;
end;

function Scan(const FileName: string; GetSig: Boolean = False): TScanResult;
var
  Cmd: string;
  ExitCode: Cardinal;
  Output: string;
  Lines: TStringList;
  I: Integer;
  Parts: TArray<string>;
begin
  if not TFile.Exists(FileName) then
    Exit(FileNotFound);

  Cmd := Format(
    '"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "%s" -DisableRemediation -Trace -Level 0x10',
    [FileName]);

  if not RunProcessCapture(Cmd, 30000, ExitCode, Output) then
    Exit(ScanError);

  if ExitCode = Cardinal(-1) then
    Exit(Timeout);

  if GetSig then
  begin
    Lines := TStringList.Create;
    try
      Lines.Text := Output;
      for I := 0 to Lines.Count - 1 do
      begin
        if Lines[I].Contains('Threat  ') then
        begin
          Parts := Lines[I].Split([' ']);
          if Length(Parts) > 19 then
            Writeln('File matched signature: "', Parts[19], '"');
          Break;
        end;
      end;
    finally
      Lines.Free;
    end;
  end;

  case ExitCode of
    0: Result := NoThreatFound;
    2: Result := ThreatFound;
  else
    Result := ScanError;
  end;
end;

procedure HexDump(const Bytes: TBytes; BytesPerLine: Integer = 16);
var
  I, J: Integer;
  B: Byte;
begin
  for I := 0 to (Length(Bytes) - 1) div BytesPerLine do
  begin
    Write(Format('%.8x   ', [I * BytesPerLine]));

    for J := 0 to BytesPerLine - 1 do
    begin
      if (I * BytesPerLine + J) < Length(Bytes) then
      begin
        B := Bytes[I * BytesPerLine + J];
        Write(Format('%.2X ', [B]));
      end
      else
        Write('   ');
    end;

    Write('  ');

    for J := 0 to BytesPerLine - 1 do
    begin
      if (I * BytesPerLine + J) < Length(Bytes) then
      begin
        B := Bytes[I * BytesPerLine + J];
        if B < 32 then
          Write('.')
        else
          Write(Char(B));
      end;
    end;

    Writeln;
  end;
end;

function HalfSplitter(const Original: TBytes; LastGood: Integer): TBytes;
var
  NewLength: Integer;
  Offending: TBytes;
begin
  NewLength := ((Length(Original) - LastGood) div 2) + LastGood;
  SetLength(Result, NewLength);

  if Length(Original) = NewLength + 1 then
  begin
    Writeln(Format('[!] Identified end of bad bytes at offset 0x%x',
      [Length(Original)]));

    Scan('C:\Temp\testfile.exe', True);

    if Length(Original) < 256 then
      Offending := Copy(Original, 0, Length(Original))
    else
      Offending := Copy(Original, Length(Original) - 256, 256);

    HexDump(Offending);
    TFile.Delete('C:\Temp\testfile.exe');
    Halt(0);
  end;

  Move(Original[0], Result[0], NewLength);
end;

function Overshot(const Original: TBytes; SplitSize: Integer): TBytes;
var
  NewSize: Integer;
begin
  NewSize := ((Length(Original) - SplitSize) div 2) + SplitSize;

  if NewSize = Length(Original) - 1 then
  begin
    Writeln('Exhausted the search. The binary looks good to go!');
    Halt(0);
  end;

  SetLength(Result, NewSize);
  Move(Original[0], Result[0], NewSize);
end;

var
  TargetFile: string;
  OriginalBytes, SplitArray: TBytes;
  LastGood: Integer;
  Detection: TScanResult;
  Debug: Boolean;

begin
  try
    if ParamCount < 1 then
    begin
      Writeln('Usage: DefenderCheck.exe [path/to/file]');
      Exit;
    end;

    TargetFile := ParamStr(1);
    Debug := (ParamCount = 2) and ParamStr(2).Contains('debug');

    if not TFile.Exists(TargetFile) then
    begin
      Writeln('[-] Can''t access the target file');
      Exit;
    end;

    Detection := Scan(TargetFile);

    if Detection = NoThreatFound then
    begin
      Writeln('[+] No threat found in submitted file!');
      Exit;
    end;

    if not TDirectory.Exists('C:\Temp') then
      TDirectory.CreateDirectory('C:\Temp');

    OriginalBytes := TFile.ReadAllBytes(TargetFile);

    Writeln('Target file size: ', Length(OriginalBytes), ' bytes');
    Writeln('Analyzing...');
    Writeln;

    SetLength(SplitArray, Length(OriginalBytes) div 2);
    Move(OriginalBytes[0], SplitArray[0], Length(SplitArray));
    LastGood := 0;

    while True do
    begin
      if Debug then
        Writeln('Testing ', Length(SplitArray), ' bytes');

      TFile.WriteAllBytes('C:\Temp\testfile.exe', SplitArray);
      Detection := Scan('C:\Temp\testfile.exe');

      if Detection = ThreatFound then
      begin
        if Debug then
          Writeln('Threat found. Halfsplitting again...');
        SplitArray := HalfSplitter(SplitArray, LastGood);
      end
      else if Detection = NoThreatFound then
      begin
        if Debug then
          Writeln('No threat found. Increasing size...');
        LastGood := Length(SplitArray);
        SplitArray := Overshot(OriginalBytes, Length(SplitArray));
      end;
    end;

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
