import pickle
import faiss
import numpy as np
import streamlit as st
from sentence_transformers import SentenceTransformer

# Load model and data
model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

with open("doc_metadata.pkl", "rb") as f:
    metadata = pickle.load(f)

index = faiss.read_index("doc_index.faiss")

# Streamlit UI
st.title("🔍 Doc Hub Smart Search")

query = st.text_input("Ask a question about the docs:")

if query:
    query_vec = model.encode([query])
    top_k = 3
    scores, indices = index.search(np.array(query_vec).astype("float32"), top_k)

    for i in range(top_k):
        idx = indices[0][i]
        st.markdown(f"**File:** `{metadata[idx]['filename']}`")
        st.write(metadata[idx]['text'])
        st.markdown("---")
