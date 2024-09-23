import logging
import azure.functions as func
import json
import redis
import os
from supportchat.chat import ChatAgent
from interviewchat.chat import InterviewAgent
from datetime import datetime
from savechat import save_chat, archive_chat

app = func.FunctionApp()

connect_instances = {}
chat_agent_instances = {}
save_chat_to_archive = False

modes = {
        "support-chat" : ChatAgent,
        "credit-interview" : InterviewAgent
    }

def create_redis_client(db):
    return redis.StrictRedis(host=os.environ['AZURE_REDIS_HOST'], 
                    port=6380, 
                    db=db, 
                    password=os.environ['AZURE_REDIS_PASSWORD'], 
                    ssl=True
                    )

redis_client = create_redis_client(2)

@app.route(route="connect", auth_level=func.AuthLevel.FUNCTION)
async def onConnect(req: func.HttpRequest) -> func.HttpResponse:

    logging.info('On connect function got triggered')

    body = req.get_body()
    logging.info(body)

    sec_websocket_protocol = req.headers.get('sec-websocket-protocol', None)
    mode, token = sec_websocket_protocol.split(", ")

    # Initialize the ChatAgent instance on connect
    try:
        connect_instances[mode+token] = modes[mode](token)
        logging.info('ChatAgent instance initialized successfully.')
        return func.HttpResponse(
                status_code=200,
                headers={"Sec-WebSocket-Protocol": mode}
            )
        # response_message = {"status": "Connection request received and ChatAgent initialized"}
    except Exception as e:
        logging.error(f'Failed to initialize ChatAgent: {str(e)}')
        return func.HttpResponse(
                status_code=403,
                mimetype="application/json",
                headers={"Sec-WebSocket-Protocol": mode}
            )
    

@app.route(route="message", auth_level=func.AuthLevel.FUNCTION)
async def onMessage(req: func.HttpRequest) -> func.HttpResponse:
    global save_chat_to_archive
    logging.info('OnMessage function got triggered')

    try:
        response_body = req.get_json()
        body_json = response_body['requestBody']
        connectionId = response_body['connectionId']
        token = body_json["token"]
        mode = body_json["action"]
    except:
        return func.HttpResponse(
                        json.dumps({"flag": "response", 
                                    "message": "Please enter your message again."}),
                        status_code=200,
                        mimetype="application/json"
                    )

    try:
        chat_agent_instances[connectionId] = connect_instances[mode+token]
    except:
        chat_agent_instances[connectionId] = modes[mode](token)

    try:
        if body_json['flag'] == "chatMessage":
            if len(body_json["message"]) > 1000:
                response = "Your input exceeds the limit of 1000 letters."
            else:
                response = chat_agent_instances[connectionId].process_chat(body_json["message"])
            return func.HttpResponse(
                        json.dumps({"flag": "response",
                                    "message": response}),
                        status_code=200,
                        mimetype="application/json"
                    )

        elif body_json['flag'] == "chatHasStarted":
            
            redis_client.hset("activeConnections", connectionId, json.dumps({"time": str(datetime.utcnow()), "username": chat_agent_instances[connectionId].username, "mode": body_json["action"], "token": body_json["token"]}))

            if chat_agent_instances[connectionId].previous_chat_history_length == 0:
                return func.HttpResponse(
                    json.dumps({"flag": "notAskQuestion", "message": "."}),
                    status_code=200,
                    mimetype="application/json"
                )
            else:
                return func.HttpResponse(
                    json.dumps({"flag": "askQuestion", 
                                "message": str(chat_agent_instances[connectionId].history_str)}),
                    status_code=200,
                    mimetype="application/json"
                )

        elif body_json["flag"] == "previousChatNotNeeded":
            save_chat_to_archive = True
            chat_agent_instances[connectionId].clear_chat_from_memory()
            return func.HttpResponse(
                json.dumps({"flag": "previousChatNotNeededResponse", "message": "Hey, how can I help you today?"}),
                status_code=200,
                mimetype="application/json"
            )
    
    except Exception as e:
        return func.HttpResponse(
                json.dumps({"flag":"error", 
                            "message": str(e)}),
                status_code=403,
                mimetype="application/json"
            )


@app.route(route="credit-interview", auth_level=func.AuthLevel.FUNCTION)
async def credit_interview(req: func.HttpRequest) -> func.HttpResponse:
    # global chat_agent_instance
    logging.info('Credit Interview function got triggered')
    
    try:
        response_json = req.get_json()
        body_json = response_json['requestBody']
        connectionId = response_json['connectionId']
        token = body_json["token"]
        mode = body_json["action"]
    except:
        return func.HttpResponse(
                        json.dumps({"flag": "response", 
                                    "message": "Please enter your response again."}),
                        status_code=200,
                        mimetype="application/json"
                    )

    try:
        chat_agent_instances[connectionId] = connect_instances[mode+token]
    except:
        chat_agent_instances[connectionId] = modes[mode](token)

    try:
        if body_json['flag'] == "chatMessage":
            if len(body_json["message"]) > 1000:
                response = "Your input exceeds the limit of 1000 letters."
            else:
                response = chat_agent_instances[connectionId].process_chat(body_json["message"])
            if response != "<terminate_interview>":
                return func.HttpResponse(
                            json.dumps({"flag": "response", 
                                        "message": response}),
                            status_code=200,
                            mimetype="application/json"
                        )
            
            else:
                return func.HttpResponse(
                        json.dumps({"flag": "response", 
                                    "message": "The interview has now ended. Please review your information in next page."}),
                        status_code=200,
                        mimetype="application/json"
                    )

        elif body_json['flag'] == "chatHasStarted":
            
            redis_client.hset("activeConnections", connectionId, json.dumps({"time": str(datetime.utcnow()), "username": chat_agent_instances[connectionId].username, "mode": body_json["action"], "token": body_json["token"]}))
            # chat_agent_instances[connectionId] = connect_instances[mode+token]
            
            if chat_agent_instances[connectionId].previous_chat_history_length == 0:
                return func.HttpResponse(
                    json.dumps({"flag": "noChatHistoryExists", "message": " "}),
                    status_code=200,
                    mimetype="application/json"
                )
            else:
                logging.info("chatHistoryExists")
                return func.HttpResponse(
                    json.dumps({"flag": "chatHistoryExists", 
                                "message": str(chat_agent_instances[connectionId].history_str)}),
                    status_code=200,
                    mimetype="application/json"
                )
    
    except Exception as e:
        logging.error("Error occurred: %s", str(e))
        return func.HttpResponse(
                json.dumps({"flag":"error", 
                            "message": str(e)}),
                status_code=403,
                mimetype="application/json"
            )


@app.route(route="disconnect", auth_level=func.AuthLevel.FUNCTION)
async def onDisconnect(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('On disconnect function got triggered')

    response_json = req.get_json()
    connectionId = response_json["connectionId"]
    logging.info(connectionId)

    chat_agent_instances[connectionId] = None

    redis_client = create_redis_client(2)
    payload = json.loads(redis_client.hget("activeConnections", connectionId))
    mode, username = payload["mode"], payload["username"]

    if save_chat_to_archive:
        archive_chat(username)
    
    try:
        save_chat(mode, username)

    except Exception as e:
        logging.info("Error in save chat")
        logging.info(str(e))

    db = 1 if mode == "credit-interview" else 0
    dis_redis_client = create_redis_client(db)
    
    dis_redis_client.delete(f"{mode}:{username}")
    redis_client.hdel("activeConnections", connectionId)

    return func.HttpResponse(status_code=200)