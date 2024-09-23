import os
import requests
import logging
import json, redis
from datetime import datetime
from io import BytesIO
from langchain_openai import AzureChatOpenAI, OpenAIEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import create_openai_functions_agent, AgentExecutor, Tool
from langchain.prompts import MessagesPlaceholder
from langchain.tools.retriever import create_retriever_tool
from langchain.memory import ConversationBufferWindowMemory
from langchain_community.retrievers import AzureAISearchRetriever
from langchain_community.chat_message_histories.redis import RedisChatMessageHistory
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from langchain_core.messages import HumanMessage, AIMessage


class ChatAgent:
    def __init__(self, token):

        self.retriever = AzureAISearchRetriever(
            content_key="chunk", top_k=4, index_name=os.environ["AZURE_AI_SEARCH_INDEX_NAME"]
        )

        self._me_call(token)
        self.blob_service_client = BlobServiceClient.from_connection_string(os.environ['AZURE_STORAGE_CONNECTION_STRING'])
        self.history = RedisChatMessageHistory(session_id = self.username, url= os.environ['AZURE_REDIS_SC_URL'], key_prefix = 'support-chat:')
        self.redis_client = redis.StrictRedis(host=os.environ['AZURE_REDIS_HOST'], port=6380, db=0, password=os.environ['AZURE_REDIS_PASSWORD'], ssl=True)
        self.redis_key = f"support-chat:{self.username}_timestamps" 

        # self._load_history()
        if len(self.history.messages) == 0:
            # If there is no previous messages cached in Redis
            self._load_history()
        else:
            # If there are previous messages cached in Redis
            self.previous_chat_history_length = len(self.history.messages)
            self.save_chat()
            self.clear_chat_from_memory()
            self._load_history()
        
        self.model = self._create_model()
        self.txt_prompt = self._get_prompt_file()
        self.prompt = self._create_prompt()
        self.agent_executor = self._create_agent_executor()

    def _create_model(self):
        return AzureChatOpenAI(
            temperature=0,
            openai_api_version=os.environ["AZURE_OPENAI_API_VERSION"],
            azure_deployment=os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT_NAME"]
        )
        
            
    def _me_call(self, token):
        try:
            url = os.environ["TRADELYNCS_ME_CALL"]
            headers = {
                "Authorization": f"Bearer {token}"
            }

            response = requests.post(url, headers=headers)
            self.user_data = response.json()
            self.username = str(self.user_data["id"])
            if "id" not in self.user_data:
                raise ValueError("Unauthorized Token")

        except Exception as e:
            logging.info(e)
        


    def _get_prompt_file(self):
        container_client = self.blob_service_client.get_container_client("tradelyncs-support-chat")
        txt_prompt = container_client.download_blob("system-prompts/prompt.txt").readall().decode('utf-8')
        return str(txt_prompt)


    def _create_prompt(self):
        # txt_prompt = self._get_prompt_file()
        return ChatPromptTemplate.from_messages([
            ("system", self.txt_prompt.format(user_data=self.user_data)),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])

    def _create_agent_executor(self):

        memory = ConversationBufferWindowMemory(
            k=10,
            memory_key="chat_history",
            return_messages=True,
            chat_memory=self.history
        )

        retriever_tools = create_retriever_tool(
            self.retriever,
            "tuningbill",
            "Use this tool if the query is about TuningBill/TradeLyncs."
        )

        agent = create_openai_functions_agent(
            llm=self.model,
            prompt=self.prompt,
            tools=[retriever_tools]
        )

        return AgentExecutor(
            agent=agent,
            tools=[retriever_tools],
            memory=memory,
            verbose=False
        )

    def process_chat(self, user_input):

        try:
            self.redis_client.lpush(self.redis_key, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
            response = self.agent_executor.invoke({"input": user_input}, config={"configurable" : {"session_id" : self.username}})["output"]
            self.redis_client.lpush(self.redis_key, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

        except Exception as e:
            error_message = str(e)
            if "content management policy" in error_message and "'code': 'content_filter'" in error_message:
                response = "Warning: Your message may contain sensitive or risky content. Please review and modify your message to comply with our content policies."
            else:
                response = "Some unexpected error occurred. Kindly refresh the page."
                logging.info(error_message)

        return response


    def _parse_history_string(self, history_str):
        history_list = []
        data = json.loads(history_str)

        for session in data.get("sessions", []):
            for message in session.get("messages", []):
                sender = message.get("sender", "")
                content = message.get("content", "")

                if sender == "user":
                    history_list.append(HumanMessage(content=content))
                elif sender == "bot":
                    history_list.append(AIMessage(content=content))
        return history_list

    def _load_history(self):
        
        container_client = self.blob_service_client.get_container_client("tradelyncs-support-chat")
        
        try:
            self.history_str = container_client.download_blob(f"chat-logs/{self.username}.json").readall().decode('utf-8')
            history_list = self._parse_history_string(self.history_str)
            self.previous_chat_history_length = len(history_list)
            self.history.add_messages(history_list)

        except Exception as e:
            print(f"Error loading chat history: {e}")
            self.previous_chat_history_length = 0

    def save_chat(self):
        
        blob_client = self.blob_service_client.get_blob_client(container="tradelyncs-support-chat", blob=f"chat-logs/{self.username}.json")
        
        messages = self.history.messages
        timestamps = self.redis_client.lrange(self.redis_key, 0, -1)# self.redis_client.get(self.redis_key)
        
        timestamps_list = []
        
        if timestamps:
            timestamps_list = [timestamp.decode('utf-8') for timestamp in timestamps]
            self.redis_client.delete(self.redis_key)
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
            logging.info("No new messages to save.")
            return
        
        # Define the new session
        session = {
            "startTime": timestamps_list[-1],
            "endTime": timestamps_list[0],
            "messages": filtered_messages
        }

        # Load the existing conversation data
        try:
            existing_data = None
            existing_blob = blob_client.download_blob().readall().decode('utf-8')
            existing_data = json.loads(existing_blob)

        except Exception as e:
            # If the blob does not exist or an error occurs, start a new conversation structure
            existing_data = {
                "conversationId": f"{self.username}_{timestamps_list[0]}",
                "sessions": []
            }

        # Ensure existing data is in the correct format
        if "sessions" not in existing_data or not isinstance(existing_data["sessions"], list):
            existing_data["sessions"] = []

        # Append the new session
        existing_data["sessions"].append(session)
        
        # Upload the updated conversation data to Blob Storage
        try:
            blob_client.upload_blob(data=BytesIO(json.dumps(existing_data, indent=4).encode('utf-8')),  overwrite=True)
            print(f"Chat saved successfully for user {self.username}.")
        except Exception as e:
            print(f"Error saving chat: {e}")
            

    def clear_chat_from_memory(self):
        self.history.clear()

    def archive_chat(self):
        blob_client = self.blob_service_client.get_blob_client(container="tradelyncs-support-chat", blob=f"chat-logs/{self.username}.json")
        existing_blob = blob_client.download_blob().readall()
        blob_client.delete_blob()
        blob_client2 = self.blob_service_client.get_blob_client(container="tradelyncs-support-chat", blob=f"chat-logs/archives/{self.username}_{datetime.utcnow()}.json")
        blob_client2.upload_blob(data=existing_blob, blob_type="BlockBlob", overwrite=True)