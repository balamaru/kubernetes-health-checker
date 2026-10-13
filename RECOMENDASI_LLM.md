# Rekomendasi LLM
Tugas cukup ringan dan akan digunakan oleh beberapa cluster, sehingga tidak perlu model yang mahal. Setiap temuan baru, LLM consume sekitar 3-5k token

| Pilihan | Model | Kenapa dipakai |
| --- | --- | --- |
| Rekomendasi | Kelas Flash/Mini/Haiku; Gemini Flash, OpenAI mini, atau Claude Haiku | Paling seimbang: murah, cepat, patuh format JSON, cukup paham Kubernetes |
| Paling hemat | Gemini Flash-Lite, OpenAI nano, atau DeepSeek (lewat `openai-compatible`) | Cukup untuk sebagian besar kasus. Naikkan ke kelas di atas kalau analisisnya terasa terlalu umum |
| Untolerant Data bocor keluar | Ollama dengan model Qwen atau Gemma ukuran 7–14B (butuh GPU 8–16 GB) | Untuk lingkungan on-prem. Kualitasnya di bawah model cloud |
| Hindari sebagai default | Model kelas Sonnet, GPT standar, atau Gemini Pro | Berlebihan untuk tugas ini. Kalau tetap mau dipakai, batasi ke temuan critical saja dengan `LLM_MIN_SEVERITY=critical` |


Perkiraan biaya dengan sekitar 50 temuan baru per hari pada kelas Flash/Mini/Haiku: ±US$3–15 per bulan. Hasil analisis disimpan, jadi pengingat dan restart tidak memanggil LLM lagi. Untuk model kelas Flash-Lite/Nano biayanya biasanya di bawah US$0,10 per hari.