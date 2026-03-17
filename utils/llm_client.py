"""
OCI GEN AI CLIENT
==================
Base LLM caller used by all 6 Doc Generator Agents
All agents call this to generate documentation
"""

import oci
import logging
import os
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger(__name__)


class LLMClient:
    """
    Wrapper around OCI Gen AI
    Used by all 6 doc generator agents
    """

    def __init__(self):
        self.endpoint   = os.getenv("OCI_GENAI_ENDPOINT")
        self.model      = os.getenv("OCI_GENAI_MODEL")
        self.compartment= os.getenv("OCI_COMPARTMENT_ID")
        self.config     = oci.config.from_file()
        self.client     = oci.generative_ai_inference.GenerativeAiInferenceClient(
            config             = self.config,
            service_endpoint   = self.endpoint,
            retry_strategy     = oci.retry.NoneRetryStrategy(),
            timeout            = (10, 240)
        )
        log.info(f"[LLMClient] Initialized with model: {self.model}")

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> str:
        """
        Call OCI Gen AI and return generated text

        Args:
            system_prompt: Instructions for the AI
            user_prompt:   The actual content to process
            max_tokens:    Max length of response

        Returns:
            Generated text as string
        """
        try:
            log.info(f"[LLMClient] Calling OCI Gen AI...")

            # Build the chat request
            chat_request = oci.generative_ai_inference.models.GenericChatRequest(
                messages=[
                    oci.generative_ai_inference.models.SystemMessage(
                        content=[
                            oci.generative_ai_inference.models.TextContent(
                                text=system_prompt
                            )
                        ]
                    ),
                    oci.generative_ai_inference.models.UserMessage(
                        content=[
                            oci.generative_ai_inference.models.TextContent(
                                text=user_prompt
                            )
                        ]
                    )
                ],
                max_tokens        = max_tokens,
                temperature       = 0.7,
                frequency_penalty = 0,
                presence_penalty  = 0,
                top_p             = 0.75,
                top_k             = -1,
                is_stream         = False
            )

            # Make the API call
            response = self.client.chat(
                chat_details=oci.generative_ai_inference.models.ChatDetails(
                    serving_mode=oci.generative_ai_inference.models.OnDemandServingMode(
                        model_id=self.model
                    ),
                    chat_request      = chat_request,
                    compartment_id    = self.compartment
                )
            )

            # Extract text from response
            result = response.data.chat_response.choices[0].message.content[0].text
            log.info(f"[LLMClient] ✅ Generated {len(result)} characters")
            return result

        except Exception as e:
            log.error(f"[LLMClient] ❌ Generation failed: {e}")
            raise e