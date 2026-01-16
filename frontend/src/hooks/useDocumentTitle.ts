import { useEffect } from 'react'

const APP_NAME = 'Artifact Keeper'

export function useDocumentTitle(title?: string) {
  useEffect(() => {
    const previousTitle = document.title
    document.title = title ? `${title} | ${APP_NAME}` : APP_NAME

    return () => {
      document.title = previousTitle
    }
  }, [title])
}

export default useDocumentTitle
