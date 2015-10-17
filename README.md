# OSS
目前该模块只支持listbucket的方法下载模块perl MakeFile.pm && make && make install 初始化安装

use OSS;
my $a = OSS->new({ali_access_key_id=>'xx',ali_secret_access_key=>'xxx'});
my $r = $a->ListBucket;
$r返回 oss 返回的结果;

