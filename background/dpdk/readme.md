to run dpdk codes:

1. compile

   first enter the code directory , and find the makefile 
   
   ```
   cd code
   cd (sketch_name,like cm,cs....)

   ```

   modify the Makefile,  substitude the 'APP' and the 'SRCS-y' to the target  executable file  name and the source file name. 
   
   ```
   \# binary namecd 
   
   APP = cs_8
   
   
   
   \# all source are stored in SRCS-y
   
SRCS-y := cs_8.c
   ```
   
   then

```
make
```



then enter the new-genetated build dir

```
cd build
```



2. then run

```
 ./app_name -l 0-7 -n 2 -- -P -p 1 --rx="(0,0,0,0)(0,1,1,1)(0,2,2,2)(0,3,3,3)(0,4,4,4)(0,5,5,5)(0,6,6,6)(0,7,7,7)"
```



app_name is the name of executable file,then this dpdk sketch app can run on 8 lcores





these codes were run in the DPDK 20.11 environment



reference:

 [39. Performance Thread Sample Application — dpdk 0.11 documentation (dpdk-docs.readthedocs.io)](https://dpdk-docs.readthedocs.io/en/latest/sample_app_ug/performance_thread.html) 





