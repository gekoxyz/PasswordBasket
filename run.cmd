javac -d bin ./src/*.java
start cmd.exe @cmd /k "cd bin && java -cp .;mysql-connector-java-8.0.23.jar Server"
start cmd.exe @cmd /k "java -cp bin Client"
pause
start cmd.exe @cmd /k "java -cp bin Client"
pause