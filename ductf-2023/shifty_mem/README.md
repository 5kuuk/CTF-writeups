once racy encode is pushed on the remote I did the following :
```bash
base64 -d <whatever file name i used to put the base64 encoding> > /tmp/exploit
chmod +x /tmp/exploit
```
and ran it together with shifty mem :
```
shifty_mem boop & /tmp/exploit boop && fg 
```
[how to run 2 programs in parallel](https://stackoverflow.com/questions/3004811/how-do-you-run-multiple-programs-in-parallel-from-a-bash-script)
