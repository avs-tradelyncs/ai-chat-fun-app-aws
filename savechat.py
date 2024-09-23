import os
import logging
import json, redis
from langchain_community.chat_message_histories.redis import RedisChatMessageHistory
from io import BytesIO
from azure.storage.blob import BlobServiceClient
from langchain_core.messages import HumanMessage

def save_chat(mode, username):
        
    sdb = 1 if mode == 'credit-interview' else 0
    blob_service_client=BlobServiceClient.from_connection_string(os.environ['AZURE_STORAGE_CONNECTION_STRING'])
    redis_client= redis.StrictRedis(host=os.environ['AZURE_REDIS_HOST'], port=6380, db=sdb, password=os.environ['AZURE_REDIS_PASSWORD'], ssl=True)
    blob_client = blob_service_client.get_blob_client(container=f"tradelyncs-{mode}", blob=f"chat-logs/{username}.json")
    
    redis_key=f"{mode}:{username}_timestamps"
    key_prefix=f"{mode}:"
    redis_url = os.environ['AZURE_REDIS_CI_URL'] if mode == "credit-interview" else os.environ['AZURE_REDIS_SC_URL']
    
    chat_history = RedisChatMessageHistory(session_id = username, url= redis_url, key_prefix = key_prefix)
    if mode == "credit-interview":
        section_pointer = int(redis_client.hget("sectionPointer", username))
    
    messages = chat_history.messages
    timestamps = redis_client.lrange(redis_key, 0, -1)# self.redis_client.get(self.redis_key)
    
    timestamps_list = []
    
    if timestamps:
        timestamps_list = [timestamp.decode('utf-8') for timestamp in timestamps]
        redis_client.delete(redis_key)
        print("Deleting client key.")

    filtered_messages = [
        {
            "timestamp": time,  # Ensure UTC timestamp
            "sender": "user" if isinstance(msg, HumanMessage) else "bot",
            "content": msg.content
        }
        for msg, time in zip(messages[-len(timestamps_list):], timestamps_list[::-1])
    ]

    # If no new messages, return without saving
    if not filtered_messages:
        if mode == "credit-interview":
            redis_client.hdel("sectionPointer", username)
        logging.info("No new messages to save.")
        return

    try:
        existing_data = None
        existing_blob = blob_client.download_blob().readall().decode('utf-8')
        existing_data = json.loads(existing_blob)

    except Exception as e:
        if mode == "credit-interview":
            existing_data = {
                "conversationId": f"{username}_{timestamps_list[0]}",
                "section_pointer": str(section_pointer),
                "sessions": []
            }
        else:
            existing_data = {
                "conversationId": f"{username}_{timestamps_list[0]}",
                "sessions": []
            }


    # Ensure existing data is in the correct format
    if "sessions" not in existing_data or not isinstance(existing_data["sessions"], list):
        existing_data["sessions"] = []

    if mode == "credit-interview":
        try:
            existing_data["sessions"][section_pointer]["messages"].extend(filtered_messages)
        except:
            new_session = {"section_pointer": section_pointer, "messages": filtered_messages}
            existing_data["sessions"].append(new_session)

        existing_data["section_pointer"] = len(existing_data["sessions"]) - 1 if len(existing_data["sessions"]) > 0 else 0
        redis_client.hdel("sectionPointer", username)
    
    elif mode == "support-chat":
        session = {
            "startTime": timestamps_list[-1],
            "endTime": timestamps_list[0],
            "messages": filtered_messages
        }
        existing_data["sessions"].append(session)

    # Upload the updated conversation data to Blob Storage
    try:
        blob_client.upload_blob(data=BytesIO(json.dumps(existing_data, indent=4).encode('utf-8')),  overwrite=True)
        logging.info(f"Chat saved successfully for user {username}.")
    except Exception as e:
        logging.info(f"Error saving chat: {e}")


def archive_chat(username):
    blob_service_client = BlobServiceClient.from_connection_string(os.environ['AZURE_STORAGE_CONNECTION_STRING'])
    blob_client = blob_service_client.get_blob_client(container="tradelyncs-support-chat", blob=f"chat-logs/{username}.json")
    existing_blob = blob_client.download_blob().readall()
    blob_client.delete_blob()
    blob_client2 = blob_service_client.get_blob_client(container="tradelyncs-support-chat", blob=f"chat-logs/archives/{username}_{datetime.utcnow()}.json")
    blob_client2.upload_blob(data=existing_blob, blob_type="BlockBlob", overwrite=True)