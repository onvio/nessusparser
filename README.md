# onvionessus
Parse and merge .nessus file into CSV

```
python3 parse-nessus.py <directory containing .nessus files [--split] [--minsev (critical, high, medium, low)]>

(--split creates a table for each ip address instead of just 1 big table)
(--minsev allows for setting the minimum level of severity to be included when generation the file)

```
#### **To-do**
*   Handle duplicate findings on the same host 
*   Combine same finding on multiple hosts
