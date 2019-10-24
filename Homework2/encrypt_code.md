##一、将png图片转换成rgba模式    
$ convert -depth 32 SSPKU.png SSPKU.rgba    
    
##二、以不同形式进行加密    
###（1）ECB    
$ gmssl enc -sms4-ecb -e -in SSPKU.rgba -out SSPKU_ECB.rgba -k XZsP@ssw0rd     
$ convert -size 150x150 -depth 32 SSPKU_ECB.rgba SSPKU_ECB.png     
###（2）CBC    
$ gmssl enc -sms4-cbc -e -in SSPKU.rgba -out SSPKU_CBC.rgba -k XZsP@ssw0rd     
$ convert -size 150x150 -depth 32 SSPKU_CBC.rgba SSPKU_CBC.png     
###（3）CTR    
$ gmssl enc -sms4-ctr -e -in SSPKU.rgba -out SSPKU_CTR.rgba -k XZsP@ssw0rd     
$ convert -size 150x150 -depth 32 SSPKU_CTR.rgba SSPKU_CTR.png    
###（4）CFB    
$ gmssl enc -sms4-cfb -e -in SSPKU.rgba -out SSPKU_CFB.rgba -k XZsP@ssw0rd     
$ convert -size 150x150 -depth 32 SSPKU_CFB.rgba SSPKU_CFB.png     

注：全部在Ubuntu系统下以命令行形式完成    