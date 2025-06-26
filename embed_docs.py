import os
import faiss
import pickle
from dotenv import load_dotenv


# Folder containing markdown docs
DOC_FOLDER = "docs"

# Load all .md files
def load_markdown_files(folder):
    docs = []
    for filename in os.listdir(folder):
        if filename.endswith(".md"):
            with open(os.path.join(folder, filename), "r", encoding="utf-8") as f:
                content = f.read()
                docs.append((filename, content))
    return docs

# Simple chunker: split text by paragraph
def chunk_text(text, chunk_size=300):
    paragraphs = text.split("\n\n")
    chunks, current = [], ""
    for para in paragraphs:
        if len(current) + len(para) < chunk_size:
            current += para + "\n\n"
        else:
            chunks.append(current.strip())
            current = para + "\n\n"
    if current.strip():
        chunks.append(current.strip())
    return chunks

from sentence_transformers import SentenceTransformer

model = SentenceTransformer("nomic-ai/nomic-embed-text-v1", trust_remote_code=True)

def get_embeddings(text_list):
    return model.encode(text_list, convert_to_numpy=True)




# Main process
def main():
    print("Loading markdown files...")
    files = load_markdown_files(DOC_FOLDER)
    
    texts, meta = [], []
    for filename, content in files:
        chunks = chunk_text(content)
        for chunk in chunks:
            texts.append(chunk)
            meta.append({"filename": filename, "text": chunk})

    print(f"Embedding {len(texts)} chunks...")
    vectors = get_embeddings(texts)

    # Build FAISS index
    index = faiss.IndexFlatL2(len(vectors[0]))
    index.add(np.array(vectors).astype("float32"))

    # Save index and metadata
    faiss.write_index(index, "doc_index.faiss")
    with open("doc_metadata.pkl", "wb") as f:
        pickle.dump(meta, f)

    print("✅ Embedding complete. Index saved as doc_index.faiss")

if __name__ == "__main__":
    import numpy as np
    main()
