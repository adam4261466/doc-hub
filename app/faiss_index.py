import faiss
import numpy as np
import os
import json
from pathlib import Path


class FaissIndex:
    def __init__(self, dim, user_id, path="data/faiss"):
        """
        Initialize FAISS index for a specific user.
        
        Args:
            dim (int): Dimension of the embeddings
            user_id (int): User ID for index isolation
            path (str): Base path for storing indices
        """
        self.user_id = user_id
        self.dim = dim
        self.index_path = os.path.join(path, f"{user_id}.faiss", f"{user_id}.index")
        self.metadata_path = os.path.join(path, f"{user_id}.faiss", f"{user_id}_metadata.json")

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.index_path), exist_ok=True)  # Ensure the directory exists

        # Load existing index or create new one
        if os.path.exists(self.index_path):
            self.index = faiss.read_index(self.index_path)
            self._load_metadata()
        else:
            # Use IndexIDMap2 which supports adding with IDs
            quantizer = faiss.IndexFlatL2(dim)
            self.index = faiss.IndexIDMap2(quantizer)
            self.metadata = []  # Store metadata for each vector
            self._save_metadata()

    def _load_metadata(self):
        """Load metadata from JSON file."""
        try:
            with open(self.metadata_path, 'r') as f:
                self.metadata = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.metadata = []

    def _save_metadata(self):
        """Save metadata to JSON file."""
        with open(self.metadata_path, 'w') as f:
            json.dump(self.metadata, f)

    def add_embeddings(self, embeddings, chunk_ids=None, chunk_metadata=None):
        """
        Add embeddings to the index with optional metadata.
        
        Args:
            embeddings (numpy.ndarray): Array of embedding vectors
            chunk_ids (list): List of chunk IDs corresponding to embeddings
            chunk_metadata (list): List of metadata dictionaries for each chunk
            
        Returns:
            list: IDs assigned to the added embeddings
        """
        if chunk_ids is None:
            # Generate sequential IDs starting from current index size
            start_id = self.index.ntotal
            chunk_ids = list(range(start_id, start_id + len(embeddings)))
        
        if chunk_metadata is None:
            chunk_metadata = [{} for _ in range(len(embeddings))]
        
        # Convert to numpy arrays with correct types
        embeddings_np = np.array(embeddings).astype("float32")
        ids_np = np.array(chunk_ids).astype("int64")
        
        # Add to index
        self.index.add_with_ids(embeddings_np, ids_np)
        
        # Update metadata
        for chunk_id, metadata in zip(chunk_ids, chunk_metadata):
            if chunk_id < len(self.metadata):
                self.metadata[chunk_id].update(metadata)
            else:
                # Extend metadata list if needed
                while len(self.metadata) <= chunk_id:
                    self.metadata.append({})
                self.metadata[chunk_id] = metadata
        
        # Save index and metadata safely
        self.save_index_safely()

        # Save index path in IndexMeta
        try:
            from .models import IndexMeta, db
            index_meta = IndexMeta(user_id=self.user_id, index_path=self.index_path)
            db.session.add(index_meta)
            db.session.commit()
        except ImportError:
            # Skip database save if models not available (e.g., in test)
            pass
        
        return chunk_ids

    def search(self, query_embedding, top_k=5):
        """
        Search for similar embeddings.
        
        Args:
            query_embedding (numpy.ndarray): Query embedding vector
            top_k (int): Number of results to return
            
        Returns:
            tuple: (distances, indices, metadata)
        """
        query_np = np.array([query_embedding]).astype("float32")
        distances, indices = self.index.search(query_np, top_k)
        
        # Get metadata for returned indices
        result_metadata = []
        for idx in indices[0]:
            if 0 <= idx < len(self.metadata):
                result_metadata.append(self.metadata[idx])
            else:
                result_metadata.append({})
        
        return distances[0], indices[0], result_metadata

    def get_index_size(self):
        """
        Get the current number of vectors in the index.
        
        Returns:
            int: Number of vectors
        """
        return self.index.ntotal

    def get_metadata(self, chunk_id):
        """
        Get metadata for a specific chunk ID.

        Args:
            chunk_id (int): Chunk ID

        Returns:
            dict: Metadata dictionary or empty dict if not found
        """
        if 0 <= chunk_id < len(self.metadata):
            return self.metadata[chunk_id]
        return {}

    def remove_id(self, chunk_id):
        """
        Remove a specific chunk ID from the index and metadata.

        Args:
            chunk_id (int): Chunk ID to remove
        """
        try:
            print(f"DEBUG: Attempting to remove chunk_id={chunk_id} from FAISS index")
            ids_to_remove = np.array([chunk_id]).astype("int64")
            size_before = self.index.ntotal
            self.index.remove_ids(ids_to_remove)
            size_after = self.index.ntotal
            print(f"DEBUG: Index size before removal: {size_before}, after: {size_after}")
            if 0 <= chunk_id < len(self.metadata):
                self.metadata[chunk_id] = {}
            self.save_index_safely()
            print(f"DEBUG: Successfully removed chunk_id={chunk_id} from FAISS index")
        except Exception as e:
            print(f"Error removing ID {chunk_id} from FAISS index: {e}")

    def rebuild_index_from_chunks(self):
        """
        Rebuild the FAISS index from all remaining chunks for this user.
        This removes any orphaned embeddings from deleted chunks.
        """
        from .models import Chunk
        from .embeddings import EmbeddingGenerator

        try:
            print(f"DEBUG: Rebuilding FAISS index for user {self.user_id}")

            # Get all remaining chunks for this user from database
            chunks = Chunk.query.filter_by(user_id=self.user_id).all()
            print(f"DEBUG: Found {len(chunks)} chunks in database for user {self.user_id}")

            if not chunks:
                # No chunks left, create empty index
                quantizer = faiss.IndexFlatL2(self.dim)
                self.index = faiss.IndexIDMap2(quantizer)
                self.metadata = []
                self.save_index_safely()
                print(f"DEBUG: Created empty FAISS index for user {self.user_id}")
                return

            # Extract chunk texts and IDs
            chunk_texts = [chunk.text for chunk in chunks]
            chunk_ids = [chunk.id for chunk in chunks]

            # Generate embeddings for all chunks
            embedder = EmbeddingGenerator()
            embeddings = embedder.embed_chunks(chunk_texts)
            print(f"DEBUG: Generated embeddings for {len(chunk_texts)} chunks")

            # Create new index
            quantizer = faiss.IndexFlatL2(self.dim)
            new_index = faiss.IndexIDMap2(quantizer)

            # Prepare metadata
            new_metadata = []
            chunk_metadata_list = []

            for chunk in chunks:
                metadata = {
                    "chunk_id": chunk.id,
                    "file_id": chunk.file_id,
                    "file_name": chunk.file.filename if chunk.file else "Unknown",
                    "start_char": chunk.start_char,
                    "end_char": chunk.end_char,
                    "length": len(chunk.text)
                }
                chunk_metadata_list.append(metadata)

                # Extend metadata list to accommodate the chunk ID
                while len(new_metadata) <= chunk.id:
                    new_metadata.append({})
                new_metadata[chunk.id] = metadata

            # Add all embeddings to new index
            embeddings_np = np.array(embeddings).astype("float32")
            ids_np = np.array(chunk_ids).astype("int64")

            new_index.add_with_ids(embeddings_np, ids_np)
            print(f"DEBUG: Added {len(chunk_ids)} embeddings to new FAISS index")

            # Replace old index with new one
            self.index = new_index
            self.metadata = new_metadata

            # Save the new index and metadata safely
            self.save_index_safely()

            print(f"DEBUG: Successfully rebuilt FAISS index for user {self.user_id} with {len(chunks)} chunks")

        except Exception as e:
            print(f"Error rebuilding FAISS index for user {self.user_id}: {e}")
            raise

    def save_index_safely(self):
        """
        Save the index and metadata safely using atomic swap.
        """
        import shutil

        tmp_index_path = os.path.join(os.path.dirname(self.index_path), "tmp.index")
        tmp_metadata_path = os.path.join(os.path.dirname(self.metadata_path), "tmp_metadata.json")

        # Step 1: Save index and metadata to temporary files
        faiss.write_index(self.index, tmp_index_path)
        with open(tmp_metadata_path, 'w') as f:
            json.dump(self.metadata, f)

        # Step 2: Verify index loads correctly
        try:
            test_index = faiss.read_index(tmp_index_path)
            if test_index.ntotal != self.index.ntotal:
                raise ValueError("Index size mismatch after save")
        except Exception as e:
            print("❌ Index verification failed:", e)
            # Clean up temp files
            if os.path.exists(tmp_index_path):
                os.remove(tmp_index_path)
            if os.path.exists(tmp_metadata_path):
                os.remove(tmp_metadata_path)
            raise e

        # Step 3: Atomically swap tmp files with live files
        shutil.move(tmp_index_path, self.index_path)
        shutil.move(tmp_metadata_path, self.metadata_path)
        print("✅ Index swapped safely.")


# Test function
if __name__ == "__main__":
    # Test with dummy data
    dim = 768
    user_id = 1
    
    index = FaissIndex(dim, user_id)
    
    # Create some dummy embeddings
    dummy_embeddings = np.random.rand(5, dim).astype("float32")
    
    # Add to index
    chunk_ids = index.add_embeddings(
        dummy_embeddings,
        chunk_metadata=[{"text": f"chunk_{i}", "length": 100} for i in range(5)]
    )
    
    print(f"Added {len(chunk_ids)} embeddings to index")
    print(f"Current index size: {index.get_index_size()}")
    
    # Test search
    query = np.random.rand(dim).astype("float32")
    distances, indices, metadata = index.search(query, top_k=3)
    
    print(f"Search results: distances={distances}, indices={indices}")
    print(f"Metadata: {metadata}")
