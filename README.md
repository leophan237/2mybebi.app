# 2mybebi

> *Một bài giảng, hai ngôn ngữ.*

**2mybebi** là ứng dụng web chạy hoàn toàn trên trình duyệt (single-file HTML, không cần backend server) hỗ trợ giáo viên và học viên tiếng Anh:
1. **Chuyển đổi slide bài giảng PowerPoint (`.pptx`) sang song ngữ** mà vẫn giữ nguyên mẫu câu, hội thoại và đáp án tiếng Anh.
2. **Biên soạn tài liệu ôn tập sau buổi học (`.docx` & `.pdf`)** từ slide `.pptx` hoặc `.pdf` bằng AI (BYOK — dùng API Key cá nhân) hoặc chế độ Offline.

---

## Tính năng chính

### 1. Tạo Slide song ngữ (`.pptx`)
- **Xử lý hàng loạt**: Tải lên nhiều tệp `.pptx` cùng lúc (tối đa `60 MB`/tệp).
- **Bảo toàn ngữ cảnh tiếng Anh**: Dịch chỉ dẫn, ghi chú và phần giải thích sang ngôn ngữ đích trong khi giữ nguyên mẫu câu, hội thoại và đáp án tiếng Anh.
- **Tự động căn chỉnh bố cục (Auto-reflow)**: Tự điều chỉnh khung chữ (`textbox`) và dịch cả `Speaker Notes`, xuất ra tệp `*_EN-<LANG>.pptx` hoặc đóng gói `.zip`.
- **Nén ảnh PPTX tích hợp (`PptxCompressor`)**: Giảm dung lượng hình ảnh độ phân giải cao ngay trong trình duyệt, hỗ trợ nén riêng từng tệp và tải bản `*_compressed.pptx`.
- **Hỗ trợ 12 ngôn ngữ đích**: Tiếng Việt (`vi`), Tiếng Nhật (`ja`), Tiếng Hàn (`ko`), Tiếng Trung giản thể (`zh`), Tiếng Trung phồn thể (`zh-Hant`), Tiếng Pháp (`fr`), Tiếng Tây Ban Nha (`es`), Tiếng Đức (`de`), Tiếng Bồ Đào Nha (`pt`), Tiếng Indonesia (`id`), Tiếng Thái (`th`), Tiếng Nga (`ru`).
- **Cơ chế dịch**: Ưu tiên Chrome Built-in `Translator` API (offline trên trình duyệt hỗ trợ) và tự động fallback sang `translate.googleapis.com`.

### 2. Biên soạn Tài liệu ôn tập sau buổi học (`.pptx`, `.pdf` → `.docx` & `.pdf`)
- **Trích xuất nội dung sâu**:
  - `.pptx`: Đọc toàn bộ slide bằng `JSZip v3.10.1` nhúng sẵn, hỗ trợ text thông thường, bảng, SmartArt (`diagramData`), sơ đồ mũi tên, từ điền khuyết và `Speaker Notes`.
  - `.pdf`: Trích xuất văn bản qua `pdf.js v3.11.174` (kèm bộ giải nén Flate fallback).
- **Phân tích cấu trúc bài học bằng AI (BYOK) hoặc Offline**:
  - Tự nhận diện bố cục từng bài học (từ vựng, ngữ pháp, mẫu câu giao tiếp thực tế, hội thoại, phát âm, ghi nhớ/bài tập) và biên soạn tài liệu ôn tập bằng ngôn ngữ đã chọn.
  - Trích dẫn trực tiếp ví dụ và mẫu câu ứng dụng từ slide gốc, hỗ trợ thẻ hội thoại 2 dòng (`dialogue`) và pill nhấn mạnh điểm ngữ pháp `[[...]]`.
- **Trình bày chuẩn Academic Aesthetic**:
  - Xem trước trực tiếp theo khổ A4 ngay trên giao diện.
  - Xuất từng bài hoặc gộp nhiều bài thành bộ tài liệu `.docx` (Word), `.pdf` (Vector PDF qua hộp thoại in của trình duyệt), hoặc tải tất cả dưới dạng `.zip`.
  - Tài liệu đầu ra sạch sẽ, không chèn footer hay tên công cụ.

---

## Nhà cung cấp AI hỗ trợ (BYOK)

API Key của bạn được lưu cục bộ trong `localStorage` của trình duyệt (`2mybebi_ai_config_v1`) và gọi `fetch()` trực tiếp từ trình duyệt tới nhà cung cấp AI (không đi qua máy chủ trung gian). Giao diện hỗ trợ nút **Hiện / Ẩn**, **Kiểm tra** kết nối (timeout 25s) và **Xóa** key.

| Nhà cung cấp | Các mô hình (Model) cấu hình sẵn | Ghi chú |
| :--- | :--- | :--- |
| **Google Gemini** | `gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-2.0-flash` | Khuyên dùng `gemini-2.5-flash` cho tốc độ nhanh và ổn định |
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`, `gpt-4.1-mini` | Hỗ trợ JSON mode chuẩn |
| **Anthropic** | `claude-sonnet-4-20250514`, `claude-3-7-sonnet-latest`, `claude-3-5-haiku-latest` | Gửi kèm header `anthropic-dangerous-direct-browser-access: true` để gọi trực tiếp từ trình duyệt |
| **OpenAI-Compatible** | Tự nhập Base URL & Model (mặc định OpenRouter `https://openrouter.ai/api/v1`, `google/gemini-2.5-flash`) | Phù hợp cho OpenRouter, Groq, Together, LM Studio, v.v. |
| **Chế độ Offline** | `offline` | Không cần API Key, tự tổng hợp theo rule cơ bản từ nội dung slide |

---

## Cấu trúc thư mục

```text
.
├── 2mybebi.html                                  # Toàn bộ ứng dụng web (HTML/CSS/JS + JSZip nhúng sẵn)
├── vercel.json                                   # Cấu hình rewrite "/" -> "/2mybebi.html" & header bảo mật cho Vercel
├── .vercelignore                                 # Loại trừ tệp mẫu/cục bộ khi upload lên Vercel
├── .gitignore                                    # Bỏ qua .DS_Store, .agents/, .vercel/, .env
├── README.md                                     # Tài liệu hướng dẫn dự án
└── output_mau/                                   # Một số tệp mẫu tham khảo
    ├── BE1_Lesson6_EN-JA_reflow_mau.pptx         # Mẫu slide PPTX song ngữ
    ├── BE1_Lesson6_Review_VI.docx                # Mẫu tài liệu ôn tập Word (.docx)
    └── BE1_Lesson6_Review_VI.pdf                 # Mẫu tài liệu ôn tập PDF (.pdf)
```

> **Lưu ý về thư viện ngoài khi chạy**: Ứng dụng dùng CDN `fonts.googleapis.com` (`Noto Sans`) và `cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js` (tải khi xử lý tệp `.pdf`). Các tác vụ tạo `.pptx`/`.docx` dùng `JSZip` đã được nhúng trực tiếp trong `2mybebi.html`.

---

## Chạy thử trên máy cá nhân (Local)

Bạn có thể mở trực tiếp tệp [`2mybebi.html`](./2mybebi.html) bằng trình duyệt (Chrome/Edge/Safari/Firefox), hoặc khởi chạy một static HTTP server nhỏ để đảm bảo mọi API trình duyệt hoạt động ổn định nhất:

```bash
python3 -m http.server 8000
```

Sau đó mở trình duyệt và truy cập:

```text
http://localhost:8000/2mybebi.html
```

---

## Hướng dẫn đẩy dự án lên GitHub

Repository đã được cấu hình sẵn `.gitignore` và commit ban đầu tại nhánh `main`. Bạn chỉ cần tạo repository trống trên GitHub rồi thêm `remote` và push:

```bash
git remote add origin https://github.com/<ten-tai-khoan>/<ten-repo>.git
git push -u origin main
```

---

## Hướng dẫn deploy lên Vercel

Dự án đã có sẵn [`vercel.json`](./vercel.json) tự động rewrite đường dẫn gốc `/` sang `/2mybebi.html` (tránh lỗi `404` khi deploy static) và [`.vercelignore`](./.vercelignore) để bỏ qua `output_mau/` giúp bản deploy nhẹ và nhanh hơn.

### Cách A: Deploy tự động qua Vercel Dashboard (Kết nối GitHub)
1. Đăng nhập [Vercel](https://vercel.com) → chọn **Add New… → Project**.
2. Chọn repository GitHub vừa push.
3. Trong phần **Configure Project**:
   - **Framework Preset**: `Other`
   - **Build Command**: *(để trống / tắt Override)*
   - **Output Directory**: `.` *(hoặc để mặc định)*
4. Nhấn **Deploy**. Mọi lần `git push` sau đó lên nhánh `main` sẽ tự động deploy bản mới.

### Cách B: Deploy nhanh bằng Vercel CLI
Nếu đã cài Node.js, chạy các lệnh sau tại thư mục dự án:

```bash
npm i -g vercel
vercel login
vercel --prod
```

*(Khi Vercel CLI hỏi `Want to modify these settings?`, giữ nguyên Output Directory là `.` và không cần lệnh build.)*
