# Changelog

Tài liệu này ghi nhận toàn bộ lịch sử phiên bản và các đợt cập nhật / deploy của **2mybebi** (đồng bộ với hộp **Nhật ký phiên bản** trong [`2mybebi.html`](./2mybebi.html)).

## v1.6.0 (15/11/2026) — Production · Mới nhất
- Nhận diện đầy đủ section divider `01`–`09` cùng phụ đề và cỡ chữ kế thừa `<a:defRPr>` trên slide bài học.
- Bóc tách tiền tố audio `[Track ...]` & lời dẫn hội thoại (`Listen and repeat.`, `Now, work in pairs...`), giữ nguyên tag tiếng Anh.
- Hỗ trợ bảng màu Theme `sysClr lastClr` và biến đổi `lumMod`/`lumOff` để chọn đúng màu chữ dịch trên thẻ nền nhạt.
- Chặn dịch nhầm đáp án ngắn đè lên dòng gạch dưới `____` và khắc phục lỗi `widenBounds` khi giải layout.
- Bổ sung hộp Nhật ký phiên bản ẩn gọn trên header, chỉ mở xem chi tiết khi bấm vào.

## v1.5.0 (15/11/2026) — Deploy #14c6be6
- Cho phép tệp `.pptx` chứa bảng biểu đồ nhúng không macro (chart `.xlsx`) vượt kiểm tra an toàn DocSecurity.
- Thay hộp chọn ngôn ngữ mặc định của trình duyệt bằng custom dropdown đồng bộ giao diện Ghibli.

## v1.4.0 (15/11/2026) — Deploy #f3134eb
- Mở rộng dung lượng tệp tải lên tối đa 600 MB cho cả 2 chế độ xử lý và bộ nén PPTX.
- Cải thiện bộ phát hiện hướng dẫn nhiều dòng, ghi chú, lưu ý và dãn tầng chống đè chữ sau dịch.

## v1.3.0 (15/11/2026) — Deploy #6409234
- Khóa chặt 3 màu bản dịch (`#000000`, `#FFFFFF`, `#1D4ED8`) theo độ sáng nền thực tế từng khung.
- Hiển thị hàng đợi nhiều tệp gọn gàng và tối ưu bố cục responsive trên điện thoại.

## v1.2.0 (15/11/2026) — Deploy #063fd10
- Gộp lô dịch ngữ cảnh GPT-6 Luna ở cấp toàn bộ bài giảng giúp tăng tốc và giảm trùng lặp.
- Tự động thu gọn cỡ chữ cục bộ, tôn trọng ranh giới ô bảng 3x2 và khung thẻ pill-box.

## v1.1.0 (15/11/2026) — Deploy #247e680
- Áp dụng giao diện Ghibli Watercolor kính mờ với font Manrope & Playfair Display.
- Bổ sung trình phát nhạc nền Piano, bộ sưu tập chibi tương tác và lớp bảo vệ DocSecurity / `/api/ai` proxy.

## v1.0.0 (14/11/2026) — Deploy #8275eb7
- Ra mắt Trợ lý bài giảng với 2 công cụ: SlideLingo (PPTX song ngữ) và Tóm tắt bài học (DOCX & PDF A4).
