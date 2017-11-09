package org.wso2.identity.oauth2.util;

import ballerina.net.http;
import ballerina.lang.messages;
import ballerina.lang.system;
import ballerina.utils;

const string authz_url = "https://localhost:9443/oauth2/authorize";
const string token_url = "https://localhost:9443/oauth2/token";

const string client_id = "4wQQHtLrn6LvWowfrpdGQc3Alpwa";
const string client_secret = "kSgfT9btSu0_wrqxP76KFe50icga";
const string callback = "http://localhost:9090/proxy/callback";
const string scope = "openid";


function buildOAuth2AuthzReq (message m, string spaName, string state) (message) {

    // TODO: we need use the spaName to retrieve the config params
    string redirectUri = authz_url + "?response_type=code&client_id=" + client_id + "&redirect_uri=" + callback +
                         "&scope=" + scope + "&state=" + state;

    system:println("OAuth2 Authz Request: " + redirectUri);
    buildRedirectMessage(m, redirectUri);
}

function buildOAuthTokenReq (string spaName, string authorization_code) (string, message) {

    // send a token request to authorization server and get the token and other stuff
    string tokenReqURL = token_url + "?grant_type=authorization_code&code=" + authorization_code + "&redirect_uri=" + callback;
    string basicAuthHeader = "Basic " + utils:base64encode(client_id + ":" + client_secret);

    message tokenReqMsg = {};
    messages:setHeader(tokenReqMsg, "Authorization", basicAuthHeader);
    messages:setHeader(tokenReqMsg, "Content-Type", "application/x-www-form-urlencoded");
    http:setContentLength(tokenReqMsg, 0);

    return tokenReqURL, tokenReqMsg;
}

function setCookie (message m, string cookieName, string cookieValue) {

    // set a cookie to response message from this resource, key:code, value:spaName
    string cookie = cookieName + "=" + cookieValue;
    messages:setHeader(m, "Set-Cookie", cookie);
}

function setHttpOnlyCookie (message m, string cookieName, string cookieValue) {

    // set a httpOnly cookie to response message from this resource, key:code, value:spaName
    string cookie = cookieName + "=" + cookieValue + "; HttpOnly";
    messages:setHeader(m, "Set-Cookie", cookie);
}

function removeCookie (message m, string cookieName) {

    // set a httpOnly cookie to response message from this resource, key:code, value:spaName
    string cookie = cookieName + "=; HttpOnly; MaxAge=-1";
    messages:setHeader(m, "Set-Cookie", cookie);
}


function buildRedirectMessage (message m, string redirectUrl) {
    http:setStatusCode(m, 302);
    messages:setHeader(m, "Location", redirectUrl);
}

function encryptMessage (string plainText) (string) {
    // TODO: dummy impl
    return utils:base64encode(plainText);
}

function decryptString (string cryptText) (string) {
    // TODO: dummy impl
    return utils:base64decode(cryptText);
}
