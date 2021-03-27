#include<sstream>
#include<list>
#include<mutex>
#include"mongoose.h"
#include<jsoncpp/json/json.h>
#include<mysql/mysql.h>
#include<iostream>
using namespace std;
namespace im{
#define MYSQL_HOST "192.168.164.128"
#define MYSQL_USER "root"
#define MYSQL_PASS 0
#define MYSQL_DB "im_system"
#define ONLINE "online"
#define OFFLINE "offline"
  class Tableuser{
    public:
      Tableuser()
        :_mysql(NULL)
      {
        //数据库的初始化
        //1.初始化操作句柄
        _mysql=mysql_init(NULL);
        if(_mysql==NULL){
          printf("init mysql instance failed!\n");
          exit(-1);
        }
        //2.连接服务器
        if(mysql_real_connect(_mysql,MYSQL_HOST,MYSQL_USER,MYSQL_PASS,MYSQL_DB,0,NULL,0)==NULL){
          printf("connent mysql server falied:%s\n",mysql_error(_mysql));
          mysql_close(_mysql);
          exit(-1);
        }
        //3.设置客户端字符编码集                                                                                             
        if(mysql_set_character_set(_mysql,"utf8")!=0){
          printf("set character falied:%s\n",mysql_error(_mysql));
          mysql_close(_mysql);
          exit(-1);
        }
        //4.选择数据库（可以不需要）
        if(mysql_select_db(_mysql,MYSQL_DB)!=0){
          printf("select db falied:%s\n",mysql_error(_mysql));
          mysql_close(_mysql);
          exit(-1);
        }
      }
      //添加用户
      bool Insert(const string& name,const string& passwd){
#define INSERT_USER "insert tb_user values(null,'%s',MD5('%s'),'%s');"
        char tmp[1024]={0};
        sprintf(tmp,INSERT_USER,name.c_str(),passwd.c_str(),OFFLINE);
        return Querysql(tmp);
      }
      //删除用户
      bool Delete(const string& name){
#define DELETE_USER "delete from tb_user where name='%s';"
        char tmp[1024]={0};
        sprintf(tmp,DELETE_USER,name.c_str());
        return Querysql(tmp);
      }
      //修改用户状态
      bool Updatestatus(const string& name,const string& status){
#define UPDATE_STATUS "update tb_user set status='%s' where name='%s';"
        char tmp[1024]={0};
        sprintf(tmp,UPDATE_STATUS,status.c_str(),name.c_str());
        return Querysql(tmp);
      }
      //修改用户密码
      bool Updatepasswd(const string& name,const string& passwd){
#define UPDATE_PASSWD "update tb_user set passwd=MD5('%s') where name='%s';"
        char tmp[1024]={0};
        sprintf(tmp,UPDATE_PASSWD,passwd.c_str(),name.c_str());
        return Querysql(tmp);
      }
      //查询一个用户信息
      bool Selectone(const string& name,Json::Value *user){
#define SELECT_ONE "select id,passwd,status from tb_user where name='%s';"
        char tmp[1024]={0};
        sprintf(tmp,SELECT_ONE,name.c_str());
        _mtx.lock();
        if(!Querysql(tmp)){
          _mtx.unlock();
          return false;
        }
        //获取结果集
        MYSQL_RES *res=mysql_store_result(_mysql);
        _mtx.unlock();
        if(res==NULL){
          printf("select one user store result failed:%s\n",mysql_error(_mysql));
          return false;
        }
        //获取数据行数
        int num_row=mysql_num_rows(res);
        if(num_row!=1){
          printf("mysql_num_rows failed:%s\n",mysql_error(_mysql));
          mysql_free_result(res);
          return false;
        }
        //获取数据列
        MYSQL_ROW row=mysql_fetch_row(res);
        (*user)["id"]=stoi(row[0]);
        (*user)["name"]=name.c_str();
        (*user)["passwd"]=row[1];
        (*user)["status"]=row[2];
        mysql_free_result(res);
        return true;
      }
      //查询所有用户信息
      bool Selectall(Json::Value *users){
#define SELECT_ALL "select id,name,passwd,status from tb_user;"
        _mtx.lock();
        if(!Querysql(SELECT_ALL)){
          _mtx.unlock();
          return false;
        }
        //获取结果集
        MYSQL_RES *res=mysql_store_result(_mysql);
        _mtx.unlock();
        if(res==NULL){
          printf("select all user store result failed:%s\n",mysql_error(_mysql));
          return false;
        }
        //获取数据行数
        int num_row=mysql_num_rows(res);
        //获取数据列
        for(int i=0;i < num_row;i++){
          MYSQL_ROW row=mysql_fetch_row(res);
          Json::Value val;
          val["id"]=stoi(row[0]);
          val["name"]=row[1];
          val["passwd"]=row[2];
          val["status"]=row[3];
          users->append(val);
        }
        mysql_free_result(res);
        return true;
      }
      //验证用户
      bool Verifyuser(const string& name,const string& passwd){
#define VERIFY_USER "select * from tb_user where name='%s' and passwd=MD5('%s');"
        char tmp[1024]={0};
        sprintf(tmp,VERIFY_USER,name.c_str(),passwd.c_str());
        _mtx.lock();
        if(!Querysql(tmp)){
          _mtx.unlock();
          return false;
        }
        //获取结果集
        MYSQL_RES *res=mysql_store_result(_mysql);
        _mtx.unlock();
        if(res==NULL){
          printf("Verifyuser user store result failed:%s\n",mysql_error(_mysql));
          return false;
        }
        //获取数据行数
        int num_row=mysql_num_rows(res);
        if(num_row!=1){
          printf("Verifyuser failed\n");
          mysql_free_result(res);
          return false;
        }
        mysql_free_result(res);
        return true;
      }
      //判断用户名是否存在
      bool Exists(const string& name){
#define EXISTS_USER "select * from tb_user where name='%s';"
        char tmp[1024]={0};
        sprintf(tmp,EXISTS_USER,name.c_str());
        _mtx.lock();
        if(!Querysql(tmp)){
          _mtx.unlock();
          return false;
        }
        //获取结果集
        MYSQL_RES *res=mysql_store_result(_mysql);
        _mtx.unlock();
        if(res==NULL){
          printf("exists user store result failed:%s\n",mysql_error(_mysql));
          return false;
        }
        //获取数据行数
        int num_row=mysql_num_rows(res);
        if(num_row!=1){
          printf("have no user\n");
          mysql_free_result(res);
          return false;
        }
        mysql_free_result(res);
        return true;
      }
      //销毁数据库操作句柄
      ~Tableuser(){
        if(_mysql!=NULL){
          mysql_close(_mysql);
        }
      }
    private:
      bool Querysql(const string &sql){
        if(mysql_query(_mysql,sql.c_str())!=0){
          printf("query sql:[%s] failed:%s\n",sql.c_str(),mysql_error(_mysql));
          return false;
        }
        return true;
      }
    private:
      MYSQL* _mysql;
      mutex _mtx;
  };
  //用于保存用户的信息
  struct session{
    uint64_t session_id;
    string name;
    double login_time;
    double last_atime;
    struct mg_connection* conn;//用户的链接
  };
  class IM{
    public:
      ~IM(){
        mg_mgr_free(&_mgr);
      }
      static bool Init(const string &port=":2800"){
        tb_user=new Tableuser();
        //初始化句柄
        mg_mgr_init(&_mgr);
        //创建监听连接
        string addr="192.168.164.128";
        addr+=port;
        _lst_http=mg_http_listen(&_mgr,addr.c_str(),callback,&_mgr);
        if(_lst_http==NULL){
          printf("http listen failed\n");
          return false;
        }
        return true;
      }
      static bool Run(){ 
        while(1){
          mg_mgr_poll(&_mgr,1000);
        }
        return true;
      }
    private:
      static int Split(const string& str,const string& sep,vector<string>*_list){
        int count=0;
        size_t idx=0,pos=0;
        while(1){
          pos=str.find(sep,idx);
          if(pos==string::npos){
            break;
          }
          _list->push_back(str.substr(idx,pos-idx));
          idx=pos+sep.size();
          count++;
        }
        if(idx<str.size()){
          _list->push_back(str.substr(idx));
        }
        return count;
      }
      static bool Getcookie(const string& cookie,const string & key,string * val){
        vector<string>ch;
        Split(cookie,"; ",&ch);
        for(const auto s:ch){
          vector<string> arr_cookie;
          Split(s,"=",&arr_cookie);
          if(arr_cookie[0]==key){
            *val=arr_cookie[1];
            return true;
          }
        }
        return false;
      }
      //创建session
      static void Createsession(struct session* s,const string name,struct mg_connection *c){
        s->name=name;
        s->session_id=(uint64_t)(mg_time()*1000000);
        s->login_time=mg_time();
        s->last_atime=mg_time();
        s->conn=c;
      }
      //删除session
      static void Deletesession(struct mg_connection *c){
        auto it=_list.begin();
        while(it!=_list.end()){
          if(it->conn==c){
            _list.erase(it);
            cout<<"delete session:"<<it->name<<endl;
            return;
          }
          it++;
        }  
      }
      //获取session
      static struct session* Getsession(struct mg_connection *c){
        auto it=_list.begin();
        while(it!=_list.end()){
          if(it->conn==c){
            return &(*it);
          }
          it++;
        }
        return NULL;
      }
      static struct session* Getsessionbyconn(struct mg_connection *c){
        auto it=_list.begin();
        while(it!=_list.end()){
          if(it->conn==c){
            return &(*it);
          }
          it++;
        }
        return NULL;
      }
      static struct session* Getsessionbyname(const string& name){
        auto it=_list.begin();
        while(it!=_list.end()){
          if(it->name==name){
            return &(*it);
          }
          it++;
        }
        return NULL;
      }
      static void Broadcast(const string & msg){
        struct mg_connection *c;
        for(c=_mgr.conns;c!=NULL;c=c->next){
          if(c->is_websocket){
            mg_ws_send(c,msg.c_str(),msg.size(),WEBSOCKET_OP_TEXT);
          }
        }
        return;
      }
      static bool reg(struct mg_connection *c,struct mg_http_message* hm){
        int status=200;
        string header="Content-Type: application/json\r\n";
        //正文中提取用户信息
        string body;
        body.assign(hm->body.ptr,hm->body.len); 
        //解析用户名密码
        Json::Value user;
        Json::Reader reader;
        bool ret=reader.parse(body,user);
        if(!ret){
          status=400;
          mg_http_reply(c,status,header.c_str(),"{\"reason\":\"请求格式错误\"}");
          return false;
        }
        //判断用户是否存在
        ret=tb_user->Exists(user["name"].asString());
        if(ret){
          status=400;
          mg_http_reply(c,status,header.c_str(),"{\"reason\":\"用户名已存在\"}"); 
          return false;
        }
        //将用户信息插入数据库
        ret=tb_user->Insert(user["name"].asString(),user["passwd"].asString());
        if(!ret){
          status=500;
          mg_http_reply(c,status,header.c_str(),"{\"reason\":\"请求格式错误\"}");
          return false;
        }
        mg_http_reply(c,status,header.c_str(),"{\"reason\":\"注册成功\"}"); 
        return true;
      }
      static bool login(struct mg_connection *c,struct mg_http_message* hm){
        int status=200;
        string rsp_body="{\"reason\":\"登录成功\"}";
        string rsp_header="Content-Type: application/json\r\n";
        string req_body;
        //提取用户信息
        req_body.assign(hm->body.ptr,hm->body.len);
        //解析用户名和密码
        Json::Value user;
        Json::Reader reader;
        bool ret=reader.parse(req_body,user);
        if(!ret){
          status=400;
          rsp_body="{\"reason\":\"请求格式错误\"}";
          mg_http_reply(c,status,rsp_header.c_str(),rsp_body.c_str());
          return false;
        }
        //用户信息验证
        ret=tb_user->Verifyuser(user["name"].asString(),user["passwd"].asString());
        if(!ret){
          status=403;
          rsp_body="{\"reason\":\"用户名或者密码错误\"}";
          mg_http_reply(c,status,rsp_header.c_str(),rsp_body.c_str());
          return false;
        }
        //登录成功
        //1.设置用户状态
        ret=tb_user->Updatestatus(user["name"].asString(),ONLINE);
        if(!ret){
          status=500;
          rsp_body="{\"reason\":\"修改用户状态出错\"}";
          mg_http_reply(c,status,rsp_header.c_str(),rsp_body.c_str());
          return false;
        }
        //2.设置cookie
        struct session s;
        Createsession(&s,user["name"].asString(),c);
        _list.push_back(s);
        stringstream cookie;
        cookie<<"Set-Cookie: SESSION_ID="<<s.session_id<<"; path=/\r\n";
        cookie<<"Set-Cookie:  NAME="<<s.name<<"; path=/\r\n";
        rsp_header+=cookie.str();
        //3.响应
        mg_http_reply(c,status,rsp_header.c_str(),rsp_body.c_str());
        return true;
      }
      static void callback(mg_connection* c,int ev,void *ev_data,void *fn_data){
        struct mg_http_message* hm=(struct mg_http_message*)ev_data;
        struct mg_ws_message* wm=(struct mg_ws_message*)ev_data;
        switch(ev){
          case MG_EV_HTTP_MSG:
            {
              if (mg_http_match_uri(hm,"/reg")){
                //注册提交表单数据请求
                reg(c,hm);
              }
              else if(mg_http_match_uri(hm,"/login")){
                //登录提交表单数据请求
                login(c,hm);
              }
              else if(mg_http_match_uri(hm,"/websocket")){
                //websocket握手请求
                //建立websocket聊天通道之前，就应该检测客户端是否登录过了 
                struct mg_str* cookie_str=mg_http_get_header(hm,"cookie");
                if(cookie_str==NULL){
                  //未登录用户
                  mg_http_reply(c,403,"Content-Type: application/json\r\n","{\"reason\":\"该用户用户未登录\"}");
                }
                string str;
                str.assign(cookie_str->ptr,cookie_str->len);
                string name;
                Getcookie(str,"NAME",&name);
                string msg=name+"加入聊天室..欢迎您!";
                Broadcast(msg);
                mg_ws_upgrade(c,hm,NULL);
              }
              else{
                //静态页面请求
                //除了登陆页面，其他页面请求之前都要检测session，如果没有则直接跳转到登陆页面
                if(hm->uri.ptr!="./www/login.html"){
                 // struct session* msg=Getsessionbyconn(c);
                 // if(msg==NULL){
                 //   hm->uri.ptr="./www/login.html";
                  }
                struct mg_http_serve_opts opts={.root_dir="./www"};
                mg_http_serve_dir(c,hm,&opts);
              }
              break;
            }
          case MG_EV_WS_MSG:
            {
              string msg;
              msg.assign(wm->data.ptr,wm->data.len);
              Broadcast(msg);
              break;
            }
          case MG_EV_CLOSE:
            {
            struct session* ss=Getsessionbyconn(c);
              if(ss!=NULL){
                string msg=ss->name+"退出聊天室,再见咯!";
                Deletesession(c);
                Broadcast(msg);
                tb_user->Updatestatus(ss->name,OFFLINE);
              }
              break;
        }
          default:
            break;
        }
        return;
      }
    private:
      string _addr;
      static struct mg_mgr _mgr; //句柄
      static struct mg_connection* _lst_http;
      static Tableuser* tb_user;
      static list<struct session> _list;
  };
  struct mg_mgr IM::_mgr;
  struct mg_connection* IM::_lst_http=NULL;
  Tableuser* IM::tb_user;
  list<struct session> IM::_list;
};
