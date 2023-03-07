ffuf -u _target_/FUZZ -w MISC/dicc.txt -sa -of csv -mc 200,201,202,203 -fl 0 -c -ac -recursion -recursion-depth 2 -s -v -o _output_/_cleantarget_-cd.csv
