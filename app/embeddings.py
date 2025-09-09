from sentence_transformers import SentenceTransformer
import numpy as np
import re

class EmbeddingGenerator:
    def __init__(self, model_name="sentence-transformers/all-mpnet-base-v2"):
        self.model = SentenceTransformer(model_name)
        self.dimension = 768  # all-mpnet-base-v2 has 768 dimensions

    def embed_text(self, text):
        return self.model.encode(text, convert_to_numpy=True)

    def embed_chunks(self, texts, max_tokens=50):
        """
        Embeds the provided texts. If a single string is provided, splits it into semantic chunks first.
        If a list of strings is provided, embeds them directly.
        """
        if isinstance(texts, str):
            # Split by sentences and line breaks
            sentences = re.split(r'(?<=[.!?])\s+|\n', texts)
            chunks = []
            current_chunk = ""
            for sentence in sentences:
                if len(current_chunk.split()) + len(sentence.split()) > max_tokens:
                    if current_chunk:
                        chunks.append(current_chunk.strip())
                    current_chunk = sentence
                else:
                    current_chunk += " " + sentence if current_chunk else sentence
            if current_chunk.strip():
                chunks.append(current_chunk.strip())
            return self.model.encode(chunks, convert_to_numpy=True)
        elif isinstance(texts, list):
            # Embed the list of texts directly
            return self.model.encode(texts, convert_to_numpy=True)
        else:
            raise ValueError("Input must be a string or list of strings")

    def get_dimension(self):
        return self.dimension


# Test function
if __name__ == "__main__":
    embedder = EmbeddingGenerator()
    test_text = (
        "Adam Kabli is a software engineering student from Mohammedia, Morocco. "
        "He has a deep interest in programming, artificial intelligence, and creating innovative projects. "
        "Every morning, he wakes up at 5 am, spends several hours studying, and then dedicates time to building his projects."
    )

    embeddings = embedder.embed_chunks(test_text, max_tokens=20)
    print(f"Embeddings shape: {embeddings.shape}")
    print(f"Embedding dimension: {embedder.get_dimension()}")
    print(f"Sample embedding (first 5 values of first chunk): {embeddings[0][:5]}")
