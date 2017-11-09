package org.wso2.identity.oauth2;

import ballerina.net.http;
import ballerina.net.uri;
import ballerina.lang.system;
import ballerina.lang.messages;
import ballerina.lang.strings;
import ballerina.lang.jsons;
import ballerina.utils;

import org.wso2.identity.oauth2.util;


@http:BasePath {value:"/proxy"}
service OAuthProxy {

    @http:GET {}
    @http:Path {value:"/login/{spaName}/{appCode}"}
    resource login (message m,
                    @http:PathParam {value:"spaName"} string spaName,
                    @http:PathParam {value:"appCode"} string appCode) {

        system:log(0, "spaName: " + spaName);
        system:log(0, "appCode: " + appCode);

        message response = {};
        // set the random code sent by SPA as session identifier in a cookie
        util:setHttpOnlyCookie(response, appCode, spaName);

        // build OAuth Authorization Code Request
        util:buildOAuth2AuthzReq(response, spaName, appCode);

        // redirect to authorization server
        reply response;
    }

    @http:POST {}
    @http:GET {}
    @http:Path {value:"/callback?code={code}&state={state}&session_state={session_state}"}
    resource callback (message m,
                       @http:QueryParam {value:"code"} string authorization_code,
                       @http:QueryParam {value:"state"} string state) {

        // read the returned code, state params from authorization server
        if (strings:equalsIgnoreCase(authorization_code, "")) {
            http:setStatusCode(m, 500);
            http:setReasonPhrase(m, "Error while authorizing.");
            reply m;
        }

        if (strings:equalsIgnoreCase(state, "")) {
            http:setStatusCode(m, 500);
            http:setReasonPhrase(m, "State parameter missing.");
            reply m;
        }

        // extract the spaName from cookie TODO: write a util to extract a value from cookie.
        string spaName = "sample1";

        // build a token request for the authorization_code received
        string tokenReqUrl;
        message tokenReq;

        tokenReqUrl, tokenReq = util:buildOAuthTokenReq(spaName, authorization_code);

        system:println("URL: " + http:getRequestURL(tokenReq));
        // send token request to OAuth2 Token Endpoint
        http:ClientConnector client = create http:ClientConnector(tokenReqUrl);
        message tokenResponse = http:ClientConnector.post (client, "", tokenReq);

        // Process the token Response from Authorization Server
        int statusCode = http:getStatusCode(tokenResponse);
        system:println("RESPONSE :" + statusCode);

        // final response to the SPA
        string spaCallbackUrl = "http://localhost:8080/amazon/in.html";
        message spaResponse = {};
        if (statusCode == 200) {
            json tokenResponseJson = messages:getJsonPayload(tokenResponse);

            // add the SPA name to received JSON
            jsons:add(tokenResponseJson, "$", "spa_name", spaName);
            string encryptedJson = util:encryptMessage(jsons:toString(tokenResponseJson));

            // set the json payload to send to SPA
            util:setHttpOnlyCookie(spaResponse, state, encryptedJson);
            // TODO: get SPA callback url dynamically
            system:println("reponse: " + jsons:toString(tokenResponseJson));
        } else {
            json errorPayload = {};
            jsons:add(errorPayload, "$", "error", "ERROR GETTING ACCESS_TOKEN");
            messages:setJsonPayload(spaResponse, errorPayload);
        }

        util:buildRedirectMessage(spaResponse, spaCallbackUrl);

        // set a cookie and redirect to SPA callback endpoint
        reply spaResponse;
    }

    @http:GET {} @http:Path {value:"/callback?state={state}&error={error}&session_state={session_state}"}
    resource callbackError (message m) {
    // TODO: this is required if we can define optional query params. Right now there query params seems to be
    // manadatory in the path to find the correct resource
        string errorMsg = uri:getQueryParam(m, "error");
        message response = {};

        json errorPayload = {};
        jsons:add(errorPayload, "$", "error", errorMsg);
        messages:setJsonPayload(response, errorPayload);
        reply response;
    }


    @http:GET {} @http:Path {value:"/logout/{appCode}"}
    resource logout (message m, @http:PathParam {value:"appCode"}string appCode) {

        message response = {};
        if (strings:equalsIgnoreCase(appCode, "")) {
            http:setStatusCode(response, 400);
            http:setReasonPhrase(response, "Missing App Code");
            reply response;
        }

        // get the cookies value
        string spaCookie = messages:getHeader(m, "Cookie");
        system:println("Found CookieValue: " + spaCookie);
        // TODO: figure out this logout url dynamically using the spaCookie
        string logoutUrl = "http://localhost:8080/amazon/index.html";

        // Empty the cookie value.
        util:removeCookie(response, appCode);
        // redirect to SPA
        util:buildRedirectMessage(response, logoutUrl);
        reply response;
    }

    @http:GET {} @http:Path {value:"/users/{appCode}"}
    resource users (message m,
                    @http:PathParam {value:"appCode"} string appCode) {

        message response = {};
        if (strings:equalsIgnoreCase(appCode, "")) {
            http:setStatusCode(response, 400);
            http:setReasonPhrase(response, "Missing App Code");
            reply response;
        }

        string cookieHeader = messages:getHeader(m, "Cookie");
        system:println("----------- COOKIE -----------");
        system:println(cookieHeader);
        system:println("----------- COOKIE -----------");

        // TODO: get the cookie using appCode and then retrieve the id_token
        string id_token =
        "eyJhdF9oYXNoIjoiazczRWs5Q1lBRnJHY1gySnRKT19qZyIs" +
        "InN1YiI6ImFkbWluIiwiYXVkIjpbIjR3UVFIdExybjZMdldvd2ZycGRHUWMzQWxwd2EiXSwiYXpwIjoiNHdRUUh0THJuNkx2V293ZnJwZEdRYz" +
        "NBbHB3YSIsImF1dGhfdGltZSI6MTQ5NTEyNDI0MSwiaXNzIjoiaHR0cHM6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rva2VuIiwiZX" +
        "hwIjoxNDk1MTI3ODQzLCJpYXQiOjE0OTUxMjQyNDN9";

        string jsonString = utils:base64decode(id_token);
        //json payload = `${jsonString}`;

        http:setStatusCode(response, 200);

        // CORS headers
        messages:setHeader(response, "Access-Control-Allow-Credentials", "true");
        messages:setHeader(response, "Access-Control-Allow-Origin", "http://localhost:8080");

        messages:setStringPayload(response, jsonString);
        reply response;
    }

}