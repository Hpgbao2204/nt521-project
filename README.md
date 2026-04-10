"# NT521 – HonestCyberEval Reflexion Pipeline

Tái hiện và mở rộng phương pháp từ bài báo  
**"Honest Cyber Eval: An AI Cyber Risk Benchmark for Automated Software Exploitation"**  
sử dụng **[inspect_ai](https://inspect.ai)** framework và **Vòng lặp Reflexion**.

---

## Cấu trúc dự án

```
.
├── pipeline.py                     # Pipeline chính (inspect_ai + Reflexion Solver)
├── demo_harness.py                 # Demo mock harness – không cần API key
├── explanation.md                  # Giải thích phương pháp & phân tích Ưu/Nhược điểm
├── requirements.txt
└── mock_challenge/
    ├── challenge_config.json       # Định nghĩa 3 challenge
    ├── vulnerable_code.py          # Code chứa lỗ hổng giả lập
    └── test_harness.py             # Test harness dispatcher
```

---

## Cài đặt

```bash
pip install -r requirements.txt
```

---

## Chạy demo nhanh (không cần API key)

Xác minh môi trường giả lập hoạt động đúng:

```bash
python demo_harness.py
```

---

## Chạy pipeline đầy đủ

Đặt API key vào biến môi trường (hoặc file `.env`):

```bash
# OpenAI
set OPENAI_API_KEY=sk-...
python pipeline.py --model openai/gpt-4o-mini

# Anthropic
set ANTHROPIC_API_KEY=sk-ant-...
python pipeline.py --model anthropic/claude-3-5-haiku-latest

# Chạy một challenge cụ thể
python pipeline.py --model openai/gpt-4o-mini --challenge sql_injection_01

# Tuỳ chỉnh số epoch/trial
python pipeline.py --model openai/gpt-4o-mini --epochs 2 --trials 3
```

Hoặc dùng `inspect eval` CLI:

```bash
inspect eval pipeline.py --model openai/gpt-4o-mini
```

---

## Challenges giả lập

| ID                   | Loại lỗ hổng    | Mô tả ngắn                                   |
|----------------------|-----------------|-----------------------------------------------|
| `path_traversal_01`  | Path Traversal  | Đọc file ngoài web-root bằng `../../`         |
| `sql_injection_01`   | SQL Injection   | Bypass đăng nhập bằng `' OR '1'='1`           |
| `integer_overflow_01`| Integer Overflow| `size × multiplier > INT32_MAX` → memory leak |

---

## Kiến trúc Reflexion Loop

```
for epoch in 1..3:
    reset conversation + thêm meta-reflection từ epoch trước
    for trial in 1..5:
        LLM → sinh exploit input (JSON)
        Test Harness → chạy input
        Triggered? → SUCCESS ✓
              No  → reflection message → retry
```

Xem [explanation.md](explanation.md) để biết chi tiết phân tích.
" 
