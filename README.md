# 渗透测试Tips - Version1.0（后续进行分类，以及美化格式）
## 希望师傅们可以分享一些个人渗透测试Tips，提交方式在下面
## 食用指南&前言

首发于tools，应各位师傅的支持以及建议，遂开了这个github，本着众人拾柴火焰高，你的一滴水，我的一滴水，最终汇聚成汪洋的渗透测试之海的想法，做一个集合渗透测试知识点，小技巧的知识库，方便大家学习，以及在实战中开拓思路，举一反三。

以下渗透测试Tips，主要用于发散思维，发散而聚合，最终可以在实战用应用出各种奇淫技巧，渗透测试个人理解本事也是一个尝试和思考的过程。

本仓库，我会不定时更新我所学到的，用到的小技巧，知识点。由于之前没有学习记录总结的好习惯，所以流失了好多知识点，小技巧。下面这些，也是这两天整理的一小小部分。后面我会不定时持续更新，并且做好分类。

也恳请希望各位大佬师傅们，能随我一起更新一些小知识点，小技巧。不用是长篇大论，一两句话描述一下即可，可以是文章中学习到的知识点，也可以是实战中遇到的有趣小技巧，也可以是国外一些BugbountyTips的翻译。

希望各位大佬师傅们，能分享一些觉得可以分享的一些小奇淫技巧~

对于个人或团队提交的渗透测试Tips，我会在每个Tips后面，以及文末署名提交人ID，也希望大佬师傅们提交的时候携带自己的ID。

## 具体提交渗透测试Tips方式如下：

1、本篇首发于Tools论坛，大家可以再Tools论坛该帖子下面留言，我会定时收集整理。
```
https://www.t00ls.net/thread-59411-1-1.html
```

2、关注公众号"洞一CyberSecurity"，进行留言，格式：渗透测试Tips-xxxxxxxx。

![123.png](https://github.com/Power7089/PenetrationTest-Tips/blob/main/img/01cyber.jpg)

3、使用本仓库提交Issues，我会定时摘取整理，然后发布到该仓库。



前期先做聚合，等达到一定的量后，我会针对每一条Tips进行分类整理。

前辈师傅们请多多支持，一起做些有趣且有意义的小事情吧~

其他兄弟们也多多支持哦，天天为奉献的师傅们进行意念祈祷，天天祝福他/她们日进斗金不脱发，赢取白富美或高富帅。

更别忘了点个Star哦~



# 正文 - 渗透测试Tips

### **知己知彼，百战不殆**

1、如果提示缺少参数，如{msg：params error}，可尝使用字典模糊测试构造参数，进一步攻击。

2、程序溢出，int最大值为2147483647，可尝试使用该值进行整数溢出，观察现象。

3、403，404响应不灰心，尝试使用dirsearch等工具探测目录。

4、验证码简单绕过：重复使用，万能验证码（0000,8888），空验证码，验证码可识别（可用PKAV HTTP Fuzzer工具识别等）

5、短信轰炸绕过：手机号前加+86有可能会绕过，手机号输入邮箱，邮箱处输入手机号

6、如果验证码有实效，可尝试一段时间内重复发送获取验证码，因为有实效，所以有可能会延长验证码的时长。

7、SQL注入时，如果数据库是Mysql，可以尝试使用&&替换and，如：`' && '1'='1`，`' %26%26 '1'='1`。

8、SQL注入时，如果数据库是Mysql，waf过滤了`=`，可尝试用`like`替代。如：`and 1 like 1`

9、JWT格式在`http://jwt.calebb.net/`可以解密，前提是要知道秘钥，可以尝试构造任意数据，看他会不会有报错信息中携带秘钥信息，可以通过`https://github.com/firebase/php-jwt`生成JWT。JWT格式`header.payload.signature`

10、如果开放了redis服务（1234端口），可以尝试使用`/actuator/redis/info`语句看是否能读取敏感信息，如：`http://www.xxx.com:1234/actuator/redis/info`

11、Gitlab平台漏洞 - CVE-2020-10977

12、API接口处，可以自己构造参数，POST形式传参，可以尝试构造为JSON格式，记得添加`content-type: application/json`，一些可尝试参数，page，size，id。

13、手机发送短信时间限制的话，可以在手机号前尝试使用特殊字符，或空格。他的逻辑应该是这样的，用户输入手机号——>后端判断该手机号是否在30秒或者60秒内请求过——>如果没有，判断发送过来的手机号是够是11位的纯数字，如果不是，去掉非数字字符——>和数据库中的手机号比对，是够存在于数据库中，如果存在那么向该手机发送验证码。

14、图片验证码可设置为空，如：code=undefined

15、自动以验证码内容，观察Cookie中，参数中是否有发送给用户的内容，可以尝试更改，可以构造钓鱼链接。

16、模板注入，在{{xxx}}中输入的命令参数可被执行，如：

```
www.baidu.com/{{1+1}}
以Python为例，列出当前目录下所有文件的Payload：{{''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].listdir('.')}}
```

17、信息收集，在搜狗搜索中选择`微信`可以搜索相关企业相关公众号资产。

18、在JS文件中搜索关键字`API`，`Swagger UI`等等，尝试寻找API接口地址。

19、swagger接口常见路径：

```
/swagger/
/api/swagger/
/swagger/ui/
/api/swagger/ui/
/swagger-ui.html/
/api/swagger-ui.html/
/user/swagger-ui.html/
/swagger/ui/
/api/swagger/ui/
/libs/swaggerui/
/api/swaggerui/
/swagger-resources/configuration/ui/
/swagger-resources/configuration/security/
```

20、swagger组件特征固定title：`Swagger UI`

21、403和401的绕过小技巧：

![c437ffd30e608e079623ee01cf1b4ca](https://github.com/Power7089/PenetrationTest-Tips/blob/main/img/403%E7%BB%95%E8%BF%87.jpg)

22、盲测目录是否存在，如果存在该目录可能会自动在URL末尾添加`/`补全。

23、Mysql中可以利用的空白字符有：`%09,%0a,%0b,%0c,%0d,%20,%a0`

24、获取账号：文库，QQ群，github泄露，借/租/买账号。

25、如果泄露阿里云的 AKSK，可以使用AKSKtools工具进一步利用。`https://xz.aliyun.com/t/8429  `    

26、如果遇见后台页面一闪而过，接着让你登录，一般使用了权限认证方式，可以用一下方式进行绕过，或者遇见401,403,302，都可以尝试使用以下方法：

```
一、GET /xxx HTTP/1.1 à403
Host: test.com
绕过：
GET /xxx HTTP/1.1 à200
Host: test.com
X-Original-URL: /xxx

二、GET /xxx HTTP/1.1 à403
Host: test.com
绕过：
GET /xxx HTTP/1.1 à200
Host: test.com
Referer: http://test.com/xxx

三、302跳转：拦截并drop跳转的数据包，使其停留在当前页面。
四、前端验证：只需要删掉对应的遮挡模块，或者是验证模块的前端代码。
```

27、gopher协议使用限制：

![640.png](https://github.com/Power7089/PenetrationTest-Tips/blob/main/img/GOpher%E5%8D%8F%E8%AE%AE.png)

28、一款生成gopher协议payload的工具：

```
https://github.com/firebroo/sec_tools
```

29、Dict协议写入流程：

```
1.写入内容；
 dict://127.0.0.1:6379/set❌test

2.设置保存路径；
dict://127.0.0.1:6379/config:set:dir:/tmp/

3.设置保存文件名；
dict://127.0.0.1:6379/config:set:dbfilename:1.png

4.保存。
dict://127.0.0.1:6379/save
```

30、CentOS 7系统利用suid提权获取Root Shell

```
https://www.freebuf.com/articles/system/244627.html
```

31、xss中<a>标签利用的payload：

```
<a href=javascript:alert(1)>xx</a>
```

32、XSS过滤了单引号，等号可以：

```
①、使用：String.fromCharCode(97,108,101,114,116,40,49,41);
为alert(1)，该方法输出的结果为字符串，可以使用eval()进行执行，即弹框操作
eval(String.fromCharCode(97,108,101,114,116,40,49,41));
②、atob函数：
eval(atob`YWxlcnQoMSk=`) 为 eval(atob`alert(1)`) 其中`为反引号
```

33、XSS过滤了单引号，等号以及圆括号，eval：

```
①、过滤了eval函数可以用其他函数去绕过，如：Function，constructor
Function`a${atob`YWxlcnQoMSk=`}```
``.constructor.constructor`a${atob`YWxlcnQoMSk=`}```
```

34、可使用下面命令查看是否处在docker虚拟机中

```
cat /proc/1/cgroup
```

35、万能密码试试`'=0#`

36、CORS漏洞验证，可以使用curl来验证：

```
curl https://www.xxxx.com -H "Origin: https://test.com" -I
检查返回包的 Access-Control-Allow-Origin 字段是否为https://test.com
```

37、在盲测目标系统是否为Shiro时，可以在Cookie中手动构造`rememebrMe=xxx`，如果返回包中Set-Cookie中存在`rememberMe=deleteMe`，则证明该系统使用了Shiro，因此可以进一步攻击。

----------------------------------------
### 2021年01月21日 - 更新分界线，整理了来自Tools师傅们留言的渗透测试Tips：

1、至于登陆后台的网站，如果有重置密码功能，但被禁用了，可以找该公司技术qq群，假装用户忘记密码，提重置密码需求，让开通功能，可以验证下是否有任意密码重置漏洞。Author By：六六

2、如果遇见后台页面一闪而过，接着让你登录，一般使用了权限认证方式:
 三、302跳转：拦截并drop跳转的数据包，使其停留在当前页面。 这个操作我每次试都是不成功的，但是可以修改返回的302为200，然后删除掉Location字段。Author By：Jokong

3、任意文件下载：/porc/self/cmdline --当前进程的cmdline参数，/var/lib/mlocate/mlocate.db --全文件路径。Author By：phage

4、容易发生短信轰炸的几个业务场景以及绕过方法：Author By：登登登Y

```
①：登录处 ②：注册处 ③：找回密码处 ④：绑定处 ⑤：活动领取处 ⑥：独特功能处 ⑦：反馈处
一般绕过限制方法：
手机号码前后加空格，86，086，0086，+86，0，00，/r,/n, 以及特殊符号等
修改cookie，变量，返回
138888888889   12位经过短信网关取前11位，导致短信轰炸
```

5、注入的时候可以试试--%0a union --%0a select 尝试绕过。Author By：zhaoze

6、注入的时候，多看order by,group by,{$var}。Author By：oops33

7、手机号前加若干`+`会造成短信轰炸。Author By：ptgeft

8、如果在旁站中发现短信验证码在response中出现，可以试试主站或者其他站点中验证码是否通用。Author By：Alex125

9、获取短信验证码时，用逗号隔开两个手机号，有可能两个手机号能获取到同一个验证码。Author By：Scorpion

---------------------------------------
### 2021年01月26日 - 更新分界线，整理了来自Tools师傅们留言的渗透测试Tips：
1、测试注入 `and ord(0x1)` ->true，`and ord(0x0)` ->false。Author By：oops33

2、遇到文件读取漏洞，除了读取配置文件，还可以尝试读取网站文件，来进行代码审计，说不定就有开发疏忽的漏洞在源代码里。Author By：iwtbhero

3、使用python快速开启http服务器：Author By：ffffffff0x

```
基于python2.x，命令如下：
python -m SimpleHTTPServer 8000
# 在当前目录起个 8000 端口的 HTTP 服务

基于python3.x，命令如下：
python -m http.server 8000
```

4、渗透时尽量不要暴露自己的 IP 地址，挂代理是必须的。Author By：ffffffff0x

- linux 下要查看自己终端是否走代理可以 curl https://ifconfig.me/ 看下返回的 IP 地址
- windows 就直接访问 https://ifconfig.me/ 即可

5、整理字典时，推荐用linux下的工具快速合并和去重。Author By：ffffffff0x

```
cat file1.txt file2.txt fileN.txt > out.txt
sort out.txt | uniq > out2.txt
```

---------------------------------------

### 更新日志
2021年01月20日 - 建立仓库，编写前言，更新渗透测试Tips 1-34 个技巧

2021年01月21日 - 整理来自tools师傅们留言的渗透测试Tips

2021年01月26日 - 整理了几天来自tools师傅们的留言以及个人的渗透测试Tips

# 贡献个人（排名不分先）

**感谢以下师傅们对本仓库，以及安全这个小圈子做的一些小贡献，开源精神永不眠！**

六六，Jokong，phage，登登登Y，zhaoze，oops33，ptgeft，Alex125，Scorpion，iwtbhero，ffffffff0x

# 贡献团队（根据贡献个数进行排名）

洞一CyberSecurity



