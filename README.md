# Strengthening Privacy-Preserving Record Linkage using Diffusion
Source code and data for our PoPETS 2022 paper 'Strengthening Privacy-Preserving Record Linkage using Diffusion'
Abstract: Linking personal records from different databases is an essential step in many data workflows. 
Privacy-Preserving Record-Linkage (PPRL) techniques have been developed to link persons despite errors in the identifiers without violating their privacy.
Designing efficient PPRL schemes with high linkage quality and a strong level of privacy protection is challenging. PPRL based on  Bloom filter encoding (BF) is currently one of the most popular methods as they offer high efficiency and linkage quality. However,  it turned out that these schemes are vulnerable to several attacks, with pattern mining and graph matching attacks considered to be the most serious by far. While several proposals have been made to strengthen BF-based PPRL schemes against these attacks, all these lack a proper security analysis or do not preserve the high efficiency and linkage quality. This paper shows that both problems can be addressed by extending the scheme with an appropriate linear diffusion layer. As opposed to previous schemes, we provide extensive theoretical and experimental analysis that confirms that the resulting scheme provides high efficiency and linkage quality \emph{and} significantly increases security against the attacks mentioned above.
