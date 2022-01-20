#include <iostream>
#include "fmt/format.h"
#include <thread>
#include <sw/redis++/redis++.h>
#include "WXBizMsgCrypt.h"
#include "json.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

using namespace std;
using namespace fmt;
using namespace httplib;
using namespace sw::redis;
using json = nlohmann::json;

int main() {
    Redis redis = Redis("tcp://127.0.0.1");
    string sToken = *( redis.hget("WEIXIN:BIGBROTHER", "Token") );
    string sEncodingAESKey = *( redis.hget("WEIXIN:BIGBROTHER", "EncodingAESKey") );
    string sCorpID = *( redis.hget("WEIXIN:BIGBROTHER", "CorpID") );
    string sSecret = *( redis.hget("WEIXIN:BIGBROTHER", "sSecret") );
    Tencent::WXBizMsgCrypt wxcpt(sToken, sEncodingAESKey, sCorpID);

    Subscriber subscriber = redis.subscriber();
    subscriber.psubscribe("MSG:LOG:WEIXIN");
    subscriber.on_pmessage([&redis, &sCorpID, &sSecret](string pattern, string channel, string msg) {
        Client cli("https://qyapi.weixin.qq.com");
        cli.enable_server_certificate_verification(false);
        string token;
        auto tokenRedis = redis.get("WEIXIN:TOKEN");
        if ( tokenRedis ) {
            token = *tokenRedis;
        } else {
            cout << "token已过期，重新获取。" << endl;
            auto resToken = cli.Get( format("/cgi-bin/gettoken?corpid={}&corpsecret={}", sCorpID, sSecret).c_str() );
            json jsToken = json::parse(resToken->body);
            token = jsToken["access_token"].get<string>();
            redis.setex("WEIXIN:TOKEN", 7000, token);
        }
        json jsonSend;
        jsonSend["touser"] = "@all";
        jsonSend["msgtype"] = "text";
        jsonSend["agentid"] = 0;
        jsonSend["text"]["content"] = msg;
        cli.Post( format("/cgi-bin/message/send?access_token={}", token).c_str(), jsonSend.dump(), "text/json");
    });

    bool bKeepRunning = true;
    thread([&subscriber, bKeepRunning] {
        while (bKeepRunning) subscriber.consume();
    }).detach();

    httplib::Server svr;
    svr.Get("/", [&wxcpt](const httplib::Request &req, httplib::Response &res) {
        string sVerifyMsgSig = req.get_param_value("msg_signature");
        string sVerifyTimeStamp = req.get_param_value("timestamp");
        string sVerifyNonce = req.get_param_value("nonce");
        string sVerifyEchoStr = req.get_param_value("echostr");
        string sEchoStr;
        wxcpt.VerifyURL(sVerifyMsgSig, sVerifyTimeStamp, sVerifyNonce, sVerifyEchoStr, sEchoStr);
        res.set_content(sEchoStr, "text/xml");
    });
    svr.Post("/", [&wxcpt](const httplib::Request &req, httplib::Response &res) {
        string sReqMsgSig = req.get_param_value("msg_signature");
        string sReqTimeStamp = req.get_param_value("timestamp");
        string sReqNonce = req.get_param_value("nonce");
        string sReqXML;  // 解密之后的明文
        wxcpt.DecryptMsg(sReqMsgSig, sReqTimeStamp, sReqNonce, req.body, sReqXML);
        string sReqContent, sReqToUserName, sReqFromUserName, sReqCreateTime;
        wxcpt.GetXmlField(sReqXML, "Content", sReqContent);
        wxcpt.GetXmlField(sReqXML, "ToUserName", sReqToUserName);
        wxcpt.GetXmlField(sReqXML, "FromUserName", sReqFromUserName);
        wxcpt.GetXmlField(sReqXML, "CreateTime", sReqCreateTime);
        cout << format("{} 收到来自 {} 的消息：{}", sReqToUserName, sReqFromUserName, sReqContent) << endl;
        string sResContent = format("收到来自{}的消息：\n{}", sReqFromUserName, sReqContent);
        string sResMsgXML = format(R"&(
<xml>
<ToUserName><![CDATA[{}]]></ToUserName>
<FromUserName><![CDATA[{}]]></FromUserName>
<CreateTime>{}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{}]]></Content>
</xml>
)&", sReqFromUserName, sReqToUserName, sReqCreateTime, sResContent);
        string sEncryptMsg;
        wxcpt.EncryptMsg(sResMsgXML, sReqTimeStamp, sReqNonce, sEncryptMsg);
        res.set_content(sEncryptMsg, "text/xml");
    });
    svr.listen("::", 19860);
}
