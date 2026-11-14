# 2mybebi

> *Một bài giảng, hai ngôn ngữ.*

**2mybebi** là ứng dụng web chạy trên Vercel gồm giao diện [`2mybebi.html`](./2mybebi.html) kết hợp Serverless Proxy bảo mật [`api/ai.js`](./api/ai.js), hỗ trợ giáo viên và học viên tiếng Anh:
1. **Chuyển đổi slide bài giảng PowerPoint (`.pptx`) sang song ngữ** — kết hợp AI ngữ cảnh (`openai/gpt-6-luna` qua OpenRouter) với bộ xử lý OpenXML giữ nguyên mẫu câu, hội thoại, đáp án tiếng Anh và tự động dàn lại bố cục.
2. **Biên soạn tài liệu ôn tập sau buổi học (`.docx` & `.pdf`)** từ slide `.pptx` hoặc `.pdf` bằng `openai/gpt-6-luna` (hoặc chế độ cơ bản khi tắt AI).

---

## Kiến trúc AI & Bảo mật (Cài Key 1 lần trên máy chủ)

Ứng dụng khóa cố định:
- **Provider**: `openrouter`
- **Model**: `openai/gpt-6-luna`
- **Server Proxy**: [`/api/ai`](./api/ai.js) đọc `process.env.OPENROUTER_API_KEY` trực tiếp trên Vercel — trình duyệt **không bao giờ lưu hay nhìn thấy API Key**.

### Các lớp bảo mật tích hợp
- **Chống lộ API Key**: Không lưu key trong `localStorage`, DOM hay bundle frontend; toàn bộ thông báo lỗi được lọc qua `redactSecrets` ở cả server và client; tự động xóa `2mybebi_ai_config_v1` cũ nếu từng tồn tại.
- **Chống lạm dụng Proxy `/api/ai`**: Kiểm tra `Origin`/`Referer` cùng host (`isOriginAllowed`), giới hạn tần suất theo IP (`40 requests/phút`), giới hạn payload `256 KB` / `160.000` ký tự, hỗ trợ tùy chọn mã truy cập một lần theo máy (`APP_ACCESS_CODE`, so khớp SHA-256 `timingSafeEqual`).
- **Chống mã độc tài liệu (`DocSecurity`)**:
  - Chặn macro (`ppt/vbaProject.bin`, `vbaData.xml`), chữ ký số (`_xmlsignatures/`), ActiveX (`ppt/activeX/`), đối tượng nhúng OLE (`ppt/embeddings/`), tệp thực thi, zip-bomb và đường dẫn `Zip-Slip`.
  - Chặn `<!DOCTYPE>` / `<!ENTITY>` (XXE) khi đọc XML OpenXML.
  - Làm sạch `.rels` và `hlinkClick`/`hlinkHover`: giữ nguyên các liên kết học tập `http://` và `https://` hợp lệ trong slide gốc, đồng thời gỡ bỏ `javascript:`, `vbscript:`, `data:`, `file:`, `ms-msdt:`, `ppaction://program` và các `oleObject`/`attachedTemplate` ngoại lai.
  - Lọc XSS/HTML/SVG, vô hiệu hóa Office DDE formula injection (`=cmd|`, `=HYPERLINK(`, `+cmd|`, `-cmd|`, `@SUM(...)*cmd|`) trong bảng/nội dung xuất ra.
  - In PDF Vector qua `Blob URL` với `<meta http-equiv="Content-Security-Policy" ... script-src 'none'>` thay cho `document.write`.

---

## Tính năng chính

### 1. Tạo Slide song ngữ (`.pptx`)
- **AI xử lý ngữ cảnh theo slide (`GPT-6 Luna`)**: Phân biệt thông minh câu hướng dẫn/tiêu đề/mục tiêu/giải thích ngữ pháp cần dịch với câu bài tập, hội thoại, đáp án cần giữ nguyên tiếng Anh; tự động chuyển về Chrome `Translator` hoặc `translate.googleapis.com` nếu tắt AI.
- **Bảo toàn mẫu câu & placeholder**: Giữ nguyên mẫu câu trong dấu `"..."`, `[placeholder]` và ký hiệu IPA `/.../` đúng chuẩn OpenXML (`p:txBody`), tự co giãn/reflow tránh đè khung và dịch `Speaker Notes`.
- **Nén ảnh PPTX tích hợp (`PptxCompressor`)** và xử lý hàng loạt tối đa `60 MB`/tệp.

### 2. Biên soạn Tài liệu ôn tập (`.pptx`, `.pdf` → `.docx` & `.pdf`)
- Trích xuất sâu văn bản, bảng, SmartArt (`diagramData`) và `Speaker Notes`.
- Xuất `.docx` (Word), `.pdf` (A4 Vector qua hộp thoại in an toàn) hoặc đóng gói `.zip` không chứa footer/tên công cụ.

### 3. Giao diện Pastel Gradient Mesh & Nhạc nền Chill thủ công
- Bố cục 2 cột rộng trên desktop (`left-rail` + `workbench`), hiệu ứng Gradient Mesh nhẹ nhàng có hỗ trợ `prefers-reduced-motion`.
- Thẻ nghe nhạc nền chill nhúng từ YouTube (chỉ phát khi người dùng tự bấm nút Play, có nút **Thu gọn / Mở trình phát**).

---

## Cấu trúc thư mục

```text
.
├── 2mybebi.html                        # Giao diện + Engine OpenXML / PDF / DocSecurity
├── api/
│   └── ai.js                           # Vercel Serverless Function proxy tới OpenRouter (GPT-6 Luna)
├── tests/
│   └── verify-security-and-ai.mjs      # Bộ kiểm thử bảo mật, OpenXML & /api/ai (Node.js)
├── vercel.json                         # Rewrite "/" -> "/2mybebi.html", CSP & timeout /api/ai
├── .vercelignore                       # Loại trừ output_mau/ và tests/ khi deploy
├── .gitignore
├── README.md
└── output_mau/                         # Tài liệu mẫu tham khảo (không deploy lên Vercel)
```

---

## Kiểm thử cục bộ & Chạy thử với Vercel CLI

### Chạy bộ kiểm thử tự động (Node >= 18, không cần cài thư viện ngoài)
```bash
node tests/verify-security-and-ai.mjs
```

### Chạy đầy đủ cả frontend + `/api/ai` trên máy cá nhân
1. Tạo biến môi trường `.env.local` (đã nằm trong `.gitignore`, **không bao giờ commit**):
   ```bash
   OPENROUTER_API_KEY=sk-or-v1-...
   # Tùy chọn nếu muốn khóa thêm 1 lớp mã truy cập khi dùng web:
   # APP_ACCESS_CODE=mat-khau-nhom-cua-ban
   ```
2. Khởi chạy bằng Vercel CLI:
   ```bash
   vercel dev
   ```
   Sau đó mở trình duyệt tại `http://localhost:3000`.

---

## Hướng dẫn cấu hình & Deploy lên Vercel

1. Đẩy mã nguồn lên GitHub:
   ```bash
   git push origin main
   ```
2. Trên **Vercel Dashboard → Project → Settings → Environment Variables**, thêm:
   - `OPENROUTER_API_KEY`: API key OpenRouter của bạn (**bắt buộc**, chọn Production + Preview).
   - `APP_ACCESS_CODE` *(tùy chọn)*: Nếu bạn muốn chỉ những người có mã này mới gọi được AI; khi bật, web tự hiện ô nhập 1 lần để lưu trên máy đó.
   - `ALLOWED_ORIGINS` *(tùy chọn)*: Tên miền custom khác nếu bạn gắn domain riêng ngoài domain mặc định của Vercel.
3. Trong **Build & Deployment**: giữ **Framework Preset** = `Other`, **Build Command** trống, **Output Directory** mặc định `.`, rồi **Redeploy** để kích hoạt Environment Variables.
