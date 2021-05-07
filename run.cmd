javac -d bin ./src/*.java
start cmd.exe @cmd /k "cd bin && java -cp .;mysql-connector-java-8.0.23.jar ServerTest"
start cmd.exe @cmd /k "java -cp bin ClientTest"
pause