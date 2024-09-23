import os
import yaml
import json
import requests
import logging
import json, redis
from datetime import datetime
from io import BytesIO
from langchain_openai import AzureChatOpenAI, OpenAIEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import create_openai_functions_agent, AgentExecutor, Tool
from langchain.prompts import MessagesPlaceholder
from langchain.memory import ConversationBufferMemory
from langchain_community.chat_message_histories.redis import RedisChatMessageHistory
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.tools import tool
import asyncio
from savechat import save_chat

def remove_empty(d):
    """ Recursively remove empty dictionaries from the given dictionary """
    if not d:
        return "EMPTY"
    if not isinstance(d, dict):
        return d
    return {k: remove_empty(v) for k, v in d.items() if v != {}}

class InterviewAgent:

    def __init__(self, token):

        self._me_call(token)
        self._get_call(token)
        self.blob_service_client = BlobServiceClient.from_connection_string(os.environ['AZURE_STORAGE_CONNECTION_STRING'])

        self.token = token
        self.history = RedisChatMessageHistory(session_id = self.username, url= os.environ['AZURE_REDIS_CI_URL'], key_prefix = 'credit-interview:')
        self.redis_client = redis.StrictRedis(host=os.environ['AZURE_REDIS_HOST'], port=6380, db=1, password=os.environ['AZURE_REDIS_PASSWORD'], ssl=True)
        self.redis_key = f"credit-interview:{self.username}_timestamps" 
        self.flag = None
        
        if len(self.history.messages) == 0:
            # If there is no previous messages cached in Redis
            self._load_history()
        else:
            # If there are previous messages cached in Redis
            self.previous_chat_history_length = len(self.history.messages)
            self.section_pointer = int(self.redis_client.hget("sectionPointer", self.username))
            self.save_chat()
            self.clear_chat_from_memory()
            self._load_history()

        exists = self.redis_client.hexists("sectionPointer", self.username)
        if not exists:
            self.section_pointer = 0
            self.redis_client.hset("sectionPointer", self.username, self.section_pointer)
        else:
            self.section_pointer = int(self.redis_client.hget("sectionPointer", self.username))
        print(self.section_pointer)

        if self.section_pointer == 0:
            self.credit_application_form = {}

        self._create_model()
        self._get_prompt_file()
        self._get_schema_file()
        
        try:
            self.system_prompt = self.txt_prompt['default'] + yaml.dump(remove_empty(self.credit_application_form)) + self.txt_prompt[self.sections[self.section_pointer]]
            self._create_prompt()      
            self._create_agent_executor()
        except:
            self.flag = "<terminate_interview>"

    
    @staticmethod
    def docstring_parameter(*sub):
        def dec(obj):
            obj.description = obj.description.format(*sub)
            return obj
        return dec
    
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
            raise Exception("Token Expired")
        

    def _get_call(self, token):
        try:
            credit_application_url = os.getenv("CREDIT_APPLICATION_URL")
            headers = {
                "Authorization": f"Bearer {token}"
            }

            credit_app_response = requests.get(credit_application_url.format(companyId=self.user_data['companyId']), headers=headers)
            if credit_app_response.json()["errors"] is not None and "Target object must not be null" in credit_app_response.json()["errors"]:
                empty = {}
                credit_app_response = requests.post(credit_application_url.format(companyId=self.user_data['companyId']), json=empty, headers=headers)
            self.credit_application_form = credit_app_response.json()["data"]["newClientCreditApplication"]

        except Exception as e:
            logging.info("Get Call failed: " + str(e))
            print(str(e))
            raise Exception("Token Expired")

    def _save_call(self, data):
        
        try:
            url = os.getenv("CREDIT_APPLICATION_URL")
            headers = {
                "Authorization": f"Bearer {self.token}"
            }
            for key in data:
                self.credit_application_form[key] = data[key] 
            logging.info(str(self.credit_application_form)) 
            print(self.credit_application_form)
            requests.post(url.format(companyId=self.user_data['companyId']), json=self.credit_application_form, headers=headers)
        
        except Exception as e:
            logging.info("Push Call Failed: " + str(e))
            print(str(e))
            raise Exception("Token Expired")
            

    def _create_model(self):
        self.model = AzureChatOpenAI(
            temperature=0.15,
            openai_api_version=os.environ["AZURE_OPENAI_API_VERSION"],
            azure_deployment=os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT_NAME"]
            )

    def _get_prompt_file(self):
        container_client = self.blob_service_client.get_container_client("tradelyncs-credit-interview")
        yamlfile = container_client.download_blob("system-prompts/prompts.yaml").readall().decode('utf-8')
        promptfile = yaml.safe_load(yamlfile)
        self.txt_prompt = promptfile

    def _get_schema_file(self):
        container_client = self.blob_service_client.get_container_client("tradelyncs-credit-interview")
        extract_prompt_file = container_client.download_blob("system-prompts/extract_prompt.json").readall().decode('utf-8')
        schema_section_json = json.loads(extract_prompt_file)
        self.schema_section = [schema_section_json[section] for section in schema_section_json]
        self.sections = list(schema_section_json.keys())


    def _create_prompt(self):
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", self.system_prompt.format(user_data=self.user_data)),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])

    def create_tools(self):

        @self.docstring_parameter(self.sections[self.section_pointer])
        @tool 
        def sec_end_tool():
            """Call this tool when the {0} section has ended."""
            try:
                self._extract_info()
                self.save_chat()
                self.section_pointer += 1
                
                self.redis_client.hset("sectionPointer", self.username, self.section_pointer)
                self.system_prompt = self.txt_prompt['default'].format(user_data=self.user_data) + yaml.dump(remove_empty(self.credit_application_form)) + self.txt_prompt[self.sections[self.section_pointer]]
                
                self.clear_chat_from_memory()
                self._create_prompt()      
                self._create_agent_executor()
                                
                return f"{self.sections[self.section_pointer - 1]} section has ended. Now asking questions for section {self.sections[self.section_pointer]}."
            
            except IndexError:
                self.flag = "<terminate_interview>"
                self.clear_chat_from_memory()
                return "The interview has now ended"

            except Exception as e:
                logging.info(e)
                print(e)

        return sec_end_tool


    def _create_agent_executor(self):

        sec_end_tool = self.create_tools()

        memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True,
            chat_memory=self.history
        )

        agent = create_openai_functions_agent(
            llm=self.model,
            prompt=self.prompt,
            tools=[sec_end_tool]
        )

        self.agent_executor = AgentExecutor(
            agent=agent,
            tools=[sec_end_tool],
            memory=memory,
            handle_parsing_errors=True,
            verbose=True,
        )


    def process_chat(self, user_input):
        if self.flag == "<terminate_interview>":
            return "<terminate_interview>"
        try:
            self.redis_client.lpush(self.redis_key, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
            response = self.agent_executor.invoke({"input": user_input}, config={"configurable" : {"session_id" : self.username}})['output']

            self.redis_client.lpush(self.redis_key, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
            logging.info("Process Chat Executed Successfully.")

        except Exception as e:
            error_message = str(e)
            if "content management policy" in error_message and "code': 'content_filter'" in error_message:
                response = "Warning: Your message may contain sensitive or risky content. Please review and modify your message to comply with our content policies."
            else:
                response = "Some unexpected error occurred. Kindly refresh the page."
                logging.info(error_message)

        return response

    def _extract_info(self):

        extraction_prompt = ChatPromptTemplate.from_messages([
            ("system", "You have to extract the information from the chat history which contains credit Interview. "),
            MessagesPlaceholder(variable_name="chat_history")
        ])

        runnable = extraction_prompt | self.model.with_structured_output(schema=self.schema_section[self.section_pointer])
        
        response= runnable.invoke({"chat_history": self.history.messages})
        self._save_call(response)


    def _parse_history_string(self, history_str):
        history_list = []
        data = json.loads(history_str)
        section_pointer = int(data["section_pointer"])
        self.redis_client.hset("sectionPointer", self.username, section_pointer)
        
        if len(data["sessions"]) == 0:
            return history_list
        
        # for session in data.get("sessions", []):
        for message in data["sessions"][-1]["messages"]:
            sender = message.get("sender", "")
            content = message.get("content", "")

            if sender == "user":
                history_list.append(HumanMessage(content=content))
            elif sender == "bot":
                history_list.append(AIMessage(content=content))
        return history_list

    def _load_history(self):
        
        container_client = self.blob_service_client.get_container_client("tradelyncs-credit-interview")
        
        try:
            self.history_str = container_client.download_blob(f"chat-logs/{self.username}.json").readall().decode('utf-8')
            history_list = self._parse_history_string(self.history_str)
            self.previous_chat_history_length = len(history_list)
            self.history.add_messages(history_list)

        except Exception as e:
            print(f"Error loading chat history: {e}")
            self.previous_chat_history_length = 0

    def clear_chat_from_memory(self):
        self.history.clear()

    def save_chat(self):
        
        blob_client = self.blob_service_client.get_blob_client(container="tradelyncs-credit-interview", blob=f"chat-logs/{self.username}.json")
        
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
            self.redis_client.hdel("sectionPointer", self.username)
            logging.info("No new messages to save.")
            return

        # Load the existing conversation data
        try:
            existing_data = None
            existing_blob = blob_client.download_blob().readall().decode('utf-8')
            existing_data = json.loads(existing_blob)

        except Exception as e:
            # If the blob does not exist or an error occurs, start a new conversation structure
            existing_data = {
                "conversationId": f"{self.username}_{timestamps_list[0]}",
                "section_pointer": str(self.section_pointer),
                "sessions": []
            }

        # Ensure existing data is in the correct format
        if "sessions" not in existing_data or not isinstance(existing_data["sessions"], list):
            existing_data["sessions"] = []

        try:
            existing_data["sessions"][self.section_pointer]["messages"].extend(filtered_messages)
        except:
            new_session = {"section_pointer": self.section_pointer, "messages": filtered_messages}
            existing_data["sessions"].append(new_session)
        
        existing_data["section_pointer"] = len(existing_data["sessions"]) - 1 if len(existing_data["sessions"]) > 0 else 0
        
        self.redis_client.hdel("sectionPointer", self.username)
        # Upload the updated conversation data to Blob Storage
        try:
            blob_client.upload_blob(data=BytesIO(json.dumps(existing_data, indent=4).encode('utf-8')),  overwrite=True)
            print(f"Chat saved successfully for user {self.username}.")
        except Exception as e:
            print(f"Error saving chat: {e}")