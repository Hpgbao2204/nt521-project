# Phân tích: HonestCyberEval – Đánh giá Tự động Khai thác Lỗ hổng bằng LLM

---

## 1. Ngữ cảnh Bài toán

### 1.1 Vấn đề thực tiễn

Kiểm thử bảo mật (penetration testing) truyền thống đòi hỏi:

| Yếu tố              | Mô tả                                               |
|---------------------|-----------------------------------------------------|
| **Nhân lực**        | Chuyên gia bảo mật có thâm niên cao                |
| **Thời gian**       | Hàng tuần để nghiên cứu mã nguồn & craft exploit   |
| **Kiến thức domain**| Sâu về từng loại lỗ hổng (CWE list, CVE data)      |
| **Chi phí**         | Rất cao → nhiều tổ chức không đủ nguồn lực         |

### 1.2 Câu hỏi nghiên cứu của bài báo

> *Liệu các Mô hình Ngôn ngữ Lớn (LLMs) có thể **tự động** tạo ra input khai thác
> lỗ hổng bảo mật – chỉ bằng zero-shot prompting?*

Bài báo **"Honest Cyber Eval"** xây dựng một **benchmark** có kiểm soát: lấy
mã nguồn **Nginx** (web server mã nguồn mở, chứa nhiều lỗ hổng đã biết), viết
*test harness* cho từng lỗ hổng, rồi đánh giá xem LLM có tự sinh được exploit
input để kích hoạt lỗ hổng hay không.

### 1.3 Vị trí của LLM trong pipeline

```
Mã nguồn có lỗ hổng
        │
        ▼
┌───────────────────┐
│  System Prompt    │  ← mô tả lỗ hổng + interface
│  (Ngữ cảnh task)  │
└───────┬───────────┘
        │
        ▼
  ┌──────────────┐
  │    LLM       │  ← sinh exploit input
  └──────┬───────┘
         │ generated input
         ▼
  ┌──────────────────┐
  │  Test Harness    │  ← chạy input vào target
  └──────┬───────────┘
         │ PASS / FAIL + stdout
         ▼
  ┌──────────────────┐        ┌──────────────┐
  │  TRIGGERED?      │──YES──▶│  SUCCESS ✓   │
  └──────┬───────────┘        └──────────────┘
         │ NO
         ▼
  Reflection Prompt → LLM → retry …
```

---

## 2. Kỹ thuật Cốt lõi – Vòng lặp Reflexion

### 2.1 Reflexion là gì?

**Reflexion** (Shinn et al., 2023) là kỹ thuật *self-improvement* cho LLM:
thay vì chỉ hỏi một lần (zero-shot), hệ thống **phản hồi kết quả thực thi
ngược lại** cho LLM, để LLM tự phân tích lỗi và tạo ra thử thách tốt hơn ở
lần sau. Không cần fine-tune hay gradient – hoàn toàn trong không gian ngôn ngữ.

### 2.2 Cấu trúc 3 Epochs × 5 Trials

```
for epoch in range(3):           # Outer: meta-reflection epoch
    │
    │  reset conversation history
    │  thêm "meta-reflection" từ epoch trước vào system prompt
    │
    └─ for trial in range(5):    # Inner: trial-level reflection
           │
           ├─ [1] LLM returns exploit input (JSON)
           ├─ [2] Test Harness executes input
           ├─ [3] Check: triggered?
           │       YES → record & RETURN (task solved)
           └─ [4]  NO → append reflection message → next trial
```

| Cấp độ | Tên       | Mục đích                                              |
|--------|-----------|-------------------------------------------------------|
| Inner  | **Trial** | Phản hồi immediate: "input A thất bại vì lý do X"   |
| Outer  | **Epoch** | Phản hồi meta: tóm tắt toàn bộ epoch → approach mới |

**Tổng tối đa:** `3 × 5 = 15 lần thử` trước khi bỏ cuộc.

### 2.3 Nội dung của Reflection Message

Mỗi lần thất bại, LLM nhận được:

```
❌ Exploit failed.
Input you tried: {"filename": "../etc/passwd"}
Harness output : "No such file: /var/www/etc/passwd"

Reflect: why did this NOT trigger the vulnerability?
What needs to change? Generate a new exploit input.
```

LLM buộc phải **suy luận** về lý do thất bại (path resolution logic) trước khi
sinh input mới → hiệu quả hơn random fuzzing.

---

## 3. Hiện thực với `inspect_ai`

### 3.1 Tại sao dùng `inspect_ai`?

`inspect_ai` (Anthropic/AISI) là framework Python chuyên cho **LLM evaluation**:

- **Task / Dataset / Sample**: chuẩn hóa experiment
- **Solver**: đơn vị xử lý có thể compose (chain, fork, …)
- **Scorer**: đo lường kết quả với metrics
- **Reproducibility**: tự động log JSON cho mỗi run

### 3.2 Mapping kiến trúc code

| Thành phần bài báo   | Tương ứng trong code             |
|----------------------|----------------------------------|
| Challenge definition | `challenge_config.json` + `Sample` |
| Test harness         | `mock_challenge/test_harness.py` |
| Reflexion agent      | `reflexion_exploit_solver()`     |
| Scoring              | `exploit_success_scorer()`       |
| Evaluation runner    | `inspect_ai.eval()`              |

---

## 4. Phân tích Ưu & Nhược điểm

### 4.1 Ưu điểm ✅

| Điểm mạnh                     | Giải thích                                                               |
|-------------------------------|-------------------------------------------------------------------------|
| **Zero-shot adaptability**    | LLM có kiến thức exploit sẵn có từ pre-training; không cần human labels |
| **Tự động cải thiện**         | Reflexion giảm random search → điều hướng đúng vào vulnerability pattern |
| **Generalize across vuln types**| Cùng pipeline chạy được path traversal, SQLi, integer overflow         |
| **Interpretable reasoning**   | LLM giải thích tại sao thử cách mới → dễ audit                          |
| **Không cần fine-tuning**     | Toàn bộ là prompt engineering; tiết kiệm chi phí huấn luyện             |

### 4.2 Nhược điểm ⚠️

| Hạn chế                          | Giải thích                                                              |
|----------------------------------|-------------------------------------------------------------------------|
| **Chi phí API**                  | 15 API calls / challenge × số challenge → tốn kém ở quy mô lớn        |
| **Non-determinism**              | Cùng prompt có thể cho kết quả khác nhau → khó reproduce 100%          |
| **Context window giới hạn**      | Lịch sử hội thoại dài (15 turns) có thể bị cắt; LLM "quên" context    |
| **Hallucination**                | LLM có thể sinh exploit "trông đúng" nhưng dựa trên lý luận sai        |
| **Overfitting vào common patterns** | Với lỗ hổng novel/zero-day, LLM không có kinh nghiệm pre-training   |
| **Phụ thuộc harness quality**    | Nếu test harness sai → LLM bị mislead → kết quả không có giá trị      |
| **Ethical & Legal risks**        | Năng lực này có thể bị dùng sai mục đích nếu không kiểm soát           |

### 4.3 So sánh với Fuzzing truyền thống

| Tiêu chí             | Fuzzing (AFL/libFuzzer) | LLM + Reflexion        |
|----------------------|-------------------------|------------------------|
| Tốc độ               | Rất cao (milions/sec)   | Chậm (seconds/query)   |
| Có hướng dẫn semantic| Không                   | Có (hiểu ngữ nghĩa)    |
| Chi phí setup        | Cao (instrumentation)   | Thấp (chỉ cần prompt)  |
| Coverage             | Cao (code coverage)     | Phụ thuộc LLM          |
| Lỗ hổng logic        | Khó phát hiện           | Có thể (reasoning)     |

---

## 5. Kết luận

Phương pháp **LLM + Reflexion Loop** không thay thế fuzzing truyền thống, mà
bổ sung cho nó: hiệu quả nhất ở **lỗ hổng cần hiểu ngữ nghĩa** (SQLi, path
traversal, logic bugs) – những nơi fuzzing ngẫu nhiên cần hàng giờ để may mắn
chạm tới. Reflexion biến mỗi lần thất bại thành bài học → hội tụ nhanh hơn
đáng kể so với zero-shot đơn thuần.

---

*Tài liệu này được sinh tự động bởi pipeline thí nghiệm. Tham khảo thêm:
[Reflexion paper](https://arxiv.org/abs/2303.11366) | [inspect_ai docs](https://inspect.ai)*
