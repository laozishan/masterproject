from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Set

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


CATEGORY_LABELS = {
    "artist": "artist",
    "genre": "genre",
    "style": "style",
}


def split_terms(value: str | None) -> List[str]:
    if not value:
        return []
    return [term.strip() for term in value.split(",") if term.strip()]


@dataclass(frozen=True)
class ArtworkProfile:
    id: int
    title: str
    artist_names: tuple[str, ...]
    genres: tuple[str, ...]
    styles: tuple[str, ...]
    text: str

    @classmethod
    def from_model(cls, artwork) -> "ArtworkProfile":
        artist_names = tuple(split_terms(artwork.artistName))
        genres = tuple(split_terms(artwork.genres))
        styles = tuple(split_terms(artwork.styles))
        description = artwork.description or ""
        text = " ".join(
            [
                artwork.title or "",
                artwork.artistName or "",
                artwork.genres or "",
                artwork.styles or "",
                artwork.media or "",
                artwork.tags or "",
                description[:1200],
            ]
        )
        return cls(
            id=artwork.id,
            title=artwork.title or "Untitled",
            artist_names=artist_names,
            genres=genres,
            styles=styles,
            text=text,
        )

    def terms_for(self, category: str) -> Set[str]:
        if category == "artist":
            return set(self.artist_names)
        if category == "genre":
            return set(self.genres)
        if category == "style":
            return set(self.styles)
        return set()


@dataclass(frozen=True)
class RecommendationResult:
    artwork_id: int
    score: float
    explanation: str
    matched_terms: Dict[str, List[str]]
    exploration_terms: Dict[str, List[str]]


class RecommendationEngine:
    def __init__(self, artworks: Sequence):
        self.profiles = [ArtworkProfile.from_model(artwork) for artwork in artworks]
        self.profile_by_id = {profile.id: profile for profile in self.profiles}
        self._build_text_index()

    def _build_text_index(self) -> None:
        corpus = [profile.text for profile in self.profiles]
        self.vectorizer = TfidfVectorizer(stop_words="english")
        self.tfidf_matrix = self.vectorizer.fit_transform(corpus) if corpus else None

    def similar_ids(self, artwork_id: int, limit: int = 10) -> List[int]:
        if self.tfidf_matrix is None or artwork_id not in self.profile_by_id:
            return []

        index = next(
            (i for i, profile in enumerate(self.profiles) if profile.id == artwork_id),
            None,
        )
        if index is None:
            return []

        scores = cosine_similarity(self.tfidf_matrix[index], self.tfidf_matrix)[0]
        ranked_indexes = scores.argsort()[::-1]
        return [
            self.profiles[i].id
            for i in ranked_indexes
            if self.profiles[i].id != artwork_id
        ][:limit]

    def recommend(
        self,
        user_preferences: Mapping[str, Mapping[str, int]],
        favorite_ids: Iterable[int],
        weights: Mapping[str, int],
        limit: int = 100,
    ) -> List[RecommendationResult]:
        favorite_ids = set(favorite_ids)
        has_preferences = any(user_preferences.get(category) for category in CATEGORY_LABELS)
        results: List[RecommendationResult] = []

        for profile in self.profiles:
            if profile.id in favorite_ids:
                continue

            if not has_preferences:
                results.append(
                    RecommendationResult(
                        artwork_id=profile.id,
                        score=0,
                        explanation=(
                            "This is a discovery pick while the system learns your taste. "
                            "Like a few artworks to make future recommendations more personal."
                        ),
                        matched_terms={category: [] for category in CATEGORY_LABELS},
                        exploration_terms={category: [] for category in CATEGORY_LABELS},
                    )
                )
                continue

            score = 0.0
            matched_terms: Dict[str, List[str]] = {}
            exploration_terms: Dict[str, List[str]] = {}

            for category in CATEGORY_LABELS:
                preferred_terms = set(user_preferences.get(category, {}).keys())
                artwork_terms = profile.terms_for(category)
                union = preferred_terms | artwork_terms
                similarity = (len(preferred_terms & artwork_terms) / len(union)) if union else 0
                weight = weights.get(category, 50)
                score += weight * similarity

                matches = sorted(preferred_terms & artwork_terms)
                matched_terms[category] = matches
                exploration_terms[category] = (
                    sorted(artwork_terms - preferred_terms) if weight < 0 else []
                )

            results.append(
                RecommendationResult(
                    artwork_id=profile.id,
                    score=score,
                    explanation=self._explain(profile, matched_terms, exploration_terms, weights),
                    matched_terms=matched_terms,
                    exploration_terms=exploration_terms,
                )
            )

        return sorted(results, key=lambda result: result.score, reverse=True)[:limit]

    def _explain(
        self,
        profile: ArtworkProfile,
        matched_terms: Mapping[str, Sequence[str]],
        exploration_terms: Mapping[str, Sequence[str]],
        weights: Mapping[str, int],
    ) -> str:
        reasons = []
        for category, label in CATEGORY_LABELS.items():
            weight = weights.get(category, 50)
            if weight > 0 and matched_terms.get(category):
                terms = ", ".join(matched_terms[category][:3])
                reasons.append(f"it shares {label} signals you liked before: {terms}")
            elif weight < 0 and exploration_terms.get(category):
                terms = ", ".join(exploration_terms[category][:3])
                reasons.append(f"it expands into less familiar {label} territory: {terms}")

        if not reasons:
            return (
                f"{profile.title} is recommended as a broader discovery candidate. "
                "It balances your current weights without repeating an obvious favorite pattern."
            )

        joined = "; ".join(reasons[:3])
        return f"{profile.title} is recommended because {joined}."
