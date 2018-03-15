<?php
/**
 * Created by PhpStorm.
 * User: wb-lj348493
 * Date: 2018/3/12
 * Time: 15:27
 */
include_once 'aliyun-php-sdk-core/Config.php';
use Sts\Request\V20150401 as Sts;

class StsTest extends PHPUnit_Framework_TestCase
{
    public function  testSts()
    {
        date_default_timezone_set("UTC");
        define("REGION_ID", "cn-shanghai");
        define("ENDPOINT", "sts.cn-shanghai.aliyuncs.com");
        define("ACCESS_KEY_ID", "sts.cn-shanghai.aliyuncs.com");
        define("ACCESS_KEY_SECRET", "sts.cn-shanghai.aliyuncs.com");
        define("CLIENT_NAME", "sts.cn-shanghai.aliyuncs.com");
        define("EXPIRE_TIME", "sts.cn-shanghai.aliyuncs.com");
        // 只允许子用户使用角色
        DefaultProfile::addEndpoint(REGION_ID, REGION_ID, "Sts", ENDPOINT);
        $iClientProfile = DefaultProfile::getProfile(REGION_ID, ACCESS_KEY_ID, ACCESS_KEY_SECRET);
        $client = new DefaultAcsClient($iClientProfile);
// 角色资源描述符，在RAM的控制台的资源详情页上可以获取
        $roleArn = "acs:ram::1521081174204619:role/test/";
// 在扮演角色(AssumeRole)时，可以附加一个授权策略，进一步限制角色的权限；
// 详情请参考《RAM使用指南》
// 此授权策略表示读取所有OSS的只读权限
        $policy = <<<POLICY
                    {
                      "Statement": [
                        {
                          "Action": [
                            "oss:Get*",
                            "oss:List*"
                          ],
                          "Effect": "Allow",
                          "Resource": "*"
                        }
                      ],
                      "Version": "1"
                    }
POLICY;
        $request = new Sts\AssumeRoleRequest();
        // RoleSessionName即临时身份的会话名称，用于区分不同的临时身份
        // 您可以使用您的客户的ID作为会话名称
        $request->setRoleSessionName(CLIENT_NAME);
        $request->setRoleArn($roleArn);
        $request->setPolicy($policy);
        $request->setDurationSeconds(EXPIRE_TIME);
        $response = $client->getAcsResponse($request);
        $this -> assertTrue($response['AssumedRoleUser']);
        $this -> assertTrue($response['Credentials']);
        $this -> assertTrue(strstr($response['AssumedRoleUser']['Arn'], $roleArn));
        $this -> assertTrue();
        $time = substr($response->Credentials->Expiration, 0, 10).' '.substr($response->Credentials->Expiration, 11, 8);
        echo $time = strtotime($time)-strtotime("now");
        $this -> assertTrue($response['Credentials']["Expiration"],EXPIRE_TIME);
    }
}






