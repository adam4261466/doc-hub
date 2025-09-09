import os
import faiss
from .models import db, Chunk, File
from PyPDF2 import PdfReader
from .embeddings import EmbeddingGenerator
from .faiss_index import FaissIndex

# Function to extract raw text from uploaded file
def extract_text(file_path):
    text = ""
    if file_path.endswith(".pdf"):
        reader = PdfReader(file_path)
        for page in reader.pages:
            text += page.extract_text() or ""
    elif file_path.endswith(".txt"):
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        raise ValueError("Unsupported file format")
    return text

# Function to split text into chunks
def chunk_text(text, chunk_size=1000, overlap=200):
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append((chunk, start, end))
        start = end - overlap
    return chunks

# Function to process a file into chunks, generate embeddings, and save to DB + FAISS
def process_file(file_id, user_id, upload_folder="data/uploads"):
    file = File.query.get(file_id)
    # Use the stored file path from the database (includes unique filename)
    file_path = file.path

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")

    # Extract text and chunk it
    raw_text = extract_text(file_path)
    chunked = chunk_text(raw_text)
    
    # Extract just the text from chunks for embedding
    chunk_texts = [text for text, start, end in chunked]
    
    # Initialize embedding generator and FAISS index
    embedder = EmbeddingGenerator()
    faiss_index = FaissIndex(dim=embedder.get_dimension(), user_id=user_id)
    
    # Generate embeddings for all chunks
    embeddings = embedder.embed_chunks(chunk_texts)
    
    # Prepare chunk metadata for FAISS
    chunk_metadata_list = []
    chunk_ids = []
    db_chunks = []
    
    for i, (text, start, end) in enumerate(chunked):
        # Create database chunk
        chunk = Chunk(
            file_id=file.id,
            user_id=user_id,
            text=text,
            start_char=start,
            end_char=end,
            chunk_metadata={
                "length": len(text),
                "file_id": file.id,
                "file_name": file.filename
            }
        )
        db.session.add(chunk)
        db_chunks.append(chunk)
    
    # Commit to get chunk IDs from database
    db.session.commit()
    
    # Now that we have database IDs, prepare metadata for FAISS
    for chunk in db_chunks:
        chunk_metadata_list.append({
            "chunk_id": chunk.id,
            "file_id": chunk.file_id,
            "file_name": file.filename,
            "start_char": chunk.start_char,
            "end_char": chunk.end_char,
            "length": len(chunk.text)
        })
        chunk_ids.append(chunk.id)
    
    # Add embeddings to FAISS index with metadata
    print(f"DEBUG: Embeddings shape: {embeddings.shape}, FAISS index size before add: {faiss_index.get_index_size()}")
    faiss_index.add_embeddings(
        embeddings=embeddings,
        chunk_ids=chunk_ids,
        chunk_metadata=chunk_metadata_list
    )
    print(f"DEBUG: FAISS index size after add: {faiss_index.get_index_size()}")

    print(f"✅ Processed {len(chunked)} chunks for file {file.filename}")
    print(f"✅ Generated embeddings and added to FAISS index for user {user_id}")
    
    return len(chunked)

# Function to search for similar chunks using FAISS
def search_similar_chunks(user_id, query_text, top_k=5):
    """
    Search for chunks similar to the query text.
    
    Args:
        user_id (int): User ID to search within
        query_text (str): Query text to search for
        top_k (int): Number of results to return
        
    Returns:
        list: List of similar chunks with metadata
    """
    embedder = EmbeddingGenerator()
    faiss_index = FaissIndex(dim=embedder.get_dimension(), user_id=user_id)


    # Generate embedding for query text
    query_embedding = embedder.embed_text(query_text)
    
    # Search FAISS index
    print(f"DEBUG: FAISS index size: {faiss_index.get_index_size()}")
    distances, indices, metadata = faiss_index.search(query_embedding, top_k=top_k)
    print(f"DEBUG: Search results - distances: {distances}, indices: {indices}")
    print(f"DEBUG: Metadata returned: {metadata}")

    # Retrieve full chunk data from database
    results = []
    for distance, chunk_id, meta in zip(distances, indices, metadata):
        print(f"DEBUG: Processing chunk_id={chunk_id}, distance={distance}")
        if chunk_id >= 0:  # Valid chunk ID
            # Convert numpy.int64 to regular Python int for database query
            chunk_id_int = int(chunk_id)
            chunk = Chunk.query.get(chunk_id_int)
            if chunk:
                results.append({
                    "chunk": chunk,
                    "distance": float(distance),
                    "metadata": meta
                })
            else:
                print(f"DEBUG: No chunk found in DB for chunk_id={chunk_id_int}, removing from index")
                faiss_index.remove_id(chunk_id_int)
        else:
            print(f"DEBUG: Invalid chunk_id={chunk_id} skipped")

    print(f"DEBUG: Found {len(results)} valid chunks")
    return results
