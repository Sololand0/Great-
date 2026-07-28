from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from huggingface_hub import InferenceClient

# إعداد FastAPI
app = FastAPI(title="Hugging Face AI Chat API")

# وضع التوكن واسم النموذج مباشرة داخل الكود
HF_TOKEN = "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"
MODEL_NAME = "mistralai/Mistral-7B-Instruct-v0.3"

# تهيئة محرك الاتصال بـ Hugging Face
client = InferenceClient(model=MODEL_NAME, token=HF_TOKEN)

# تحديد هيكل رسالة الشات الواحدة
class Message(BaseModel):
    role: str      # يمكن أن يكون: 'system' أو 'user' أو 'assistant'
    content: str   # نص الرسالة

# تحديد هيكل الطلب الكامل (يستقبل مصفوفة رسائل للحفاظ على سياق المحادثة)
class ChatRequest(BaseModel):
    messages: list[Message]
    temperature: float = 0.7
    max_tokens: int = 500

@app.post("/chat")
async def chat_with_ai(request: ChatRequest):
    """
    نقطة اتصال تستقبل تاريخ المحادثة وترسلها إلى نموذج الذكاء الاصطناعي
    """
    if not request.messages:
        raise HTTPException(status_code=400, detail="قائمة الرسائل لا يمكن أن تكون فارغة")

    try:
        # تحويل البيانات القادمة إلى التنسيق المطلوب للموديل
        formatted_messages = [
            {"role": msg.role, "content": msg.content} for msg in request.messages
        ]

        # إرسال الطلب واستقبال الإجابة من سيرفرات Hugging Face
        response = client.chat_completion(
            messages=formatted_messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature
        )

        # استخراج نص الإجابة النهائي
        ai_response = response.choices.message.content
        
        return {"response": ai_response}

    except Exception as e:
        # عرض الخطأ في حال حدوث مشكلة في الاتصال أو التوكن
        raise HTTPException(status_code=500, detail=f"خطأ في محرك الذكاء الاصطناعي: {str(e)}")
