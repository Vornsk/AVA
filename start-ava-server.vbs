' AVA 서버를 콘솔 창 없이 백그라운드로 실행 (작업 스케줄러 로그온 트리거에서 호출)
' wscript가 exe 종료까지 대기(부모로 계속 상주) -> 작업 job이 닫히지 않아 서버가 유지됨.
' 창 스타일 0 = 숨김. wscript.exe는 콘솔이 없어 창이 뜨지 않음.
Dim shell
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = "C:\AVA\AVA\backend"
shell.Run """C:\AVA\AVA\backend\proxy-poc.exe""", 0, True
