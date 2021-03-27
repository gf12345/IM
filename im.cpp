#include"im.hpp"
int main(){
  im::Tableuser tu;
  //tu.Insert("lisi","123");
  //cout<<tu.Exists("lisi")<<endl;
  //cout<<tu.Exists("wangwu")<<endl;
  //Json::Value val;
  //tu.Selectone("zhangsan",&val);
  //Json::StyledWriter w;
  //cout<<w.write(val)<<endl;
  im::IM _im;
  _im.Init();
  _im.Run();
  return 0;
}
