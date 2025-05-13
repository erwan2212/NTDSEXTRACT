# NTDSEXTRACT
 Decrypt NTDS (aka NT Directory Service) active directory hashes for servers up to windows 2012r2 (rc4) and windows 2016 and up (aes).<br/>
 NTDS uses the Extensible Storage Engine format (aka ESE).<br/>
 <br/>
 syntax is NTDSEXTRACT 32_hex_chars_syskey path_to_ntds_db
 <br/><br/>
 You can dump all necessary files (registry hives and ntds database) with<br/>
 powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"<br/>
 <br/>
 check the database with esentutl /g ntds.dit and repair it with esentutl /p ntds.dit.<br/>
