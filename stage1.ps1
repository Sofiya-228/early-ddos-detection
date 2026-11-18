param(
	[string]$PythonExe = 'python'
)

$ErrorActionPreference = 'Stop'
$editcap = 'C:\Program Files\Wireshark\editcap.exe'
$capinfos = 'C:\Program Files\Wireshark\capinfos.exe'
$full = 'data\raw\Friday-WorkingHours.pcap'
$clip = 'data\processed\friday_excerpt.pcap'

Push-Location $PSScriptRoot
try {
	if (-not (Test-Path $full)) { throw "Не найден PCAP: $full" }
	if (-not (Test-Path $editcap)) { throw "Не найден Editcap: $editcap" }
	if (-not (Test-Path $capinfos)) { throw "Не найден Capinfos: $capinfos" }
	New-Item -ItemType Directory -Force -Path 'data\processed', 'results' | Out-Null

	# Выделение периода перед атакой, во время неё и после.
	& $editcap -A '2017-07-07 22:30:00' -B '2017-07-07 23:25:00' $full $clip
	if ($LASTEXITCODE -ne 0) { throw 'Ошибка Editcap' }
	& $capinfos -a -e -c -s $clip
	if ($LASTEXITCODE -ne 0) { throw 'Ошибка Capinfos' }

	# Формирование признаков и контроль временных границ.
	& $PythonExe 'src\pcap_2s_windows.py' --pcap $clip --output 'data\processed\friday_2s.csv' --window 2 --step 1
	if ($LASTEXITCODE -ne 0) { throw 'Ошибка расчёта окон' }
	& $PythonExe 'inspect_features.py'
	if ($LASTEXITCODE -ne 0) { throw 'Ошибка проверки признаков' }
	& $PythonExe 'verify_attack.py'
	if ($LASTEXITCODE -ne 0) { throw 'Ошибка проверки адресов' }
}
finally {
	Pop-Location
}
